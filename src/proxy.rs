use std::{
    net::{IpAddr, Ipv4Addr},
    num::NonZeroU32,
    sync::Arc,
    time::Duration,
};

use futures::{SinkExt, StreamExt};

use governor::{
    clock::{self},
    middleware::NoOpMiddleware,
    state::{InMemoryState, NotKeyed},
    Quota,
};

use shroom_net::{
    codec::{legacy::LegacyCodec, ShroomCodec},
    ShroomConn,
};
use tokio::{
    net::{TcpListener, TcpStream},
    time::timeout,
};

use tokio_stream::wrappers::TcpListenerStream;

use crate::{
    ip_limiter::{IpConnectionHolder, IpLimiter},
    proxy_conn::{ProxyConn, ProxyConnector},
};

//const PACKET_LEN_LIMIT: usize = 8 * 1024;

type RemoteConn = ShroomConn<LegacyCodec>;

pub type RateLimiter =
    governor::RateLimiter<NotKeyed, InMemoryState, clock::DefaultClock, NoOpMiddleware>;
    
pub struct ProxySession {
    server: ProxyConn,
    remote: RemoteConn,
    timeout: Duration,
    limit_s: RateLimiter,
    limit_m: RateLimiter,
    _conn_holder: IpConnectionHolder,
}

impl ProxySession {
    pub fn new(
        server: ProxyConn,
        remote: RemoteConn,
        cfg: &ProxyConfig,
        conn_holder: IpConnectionHolder,
    ) -> Self {
        Self {
            server,
            remote,
            timeout: cfg.timeout,
            limit_s: RateLimiter::direct(Quota::per_second(cfg.traffic_limit_sec)),
            limit_m: RateLimiter::direct(Quota::per_minute(cfg.traffic_limit_min)),
            _conn_holder: conn_holder,
        }
    }

    pub async fn run(mut self) -> anyhow::Result<()> {
        let (remote_r, remote_w) = self.remote.split();
        let (mut server_w, mut server_r) = self.server.split();

        log::info!("Running proxy: {}", self.timeout.as_nanos());

        let reader = async move {
            while let Some(pkt) = remote_r.next().await {
                let pkt = pkt?;
                let n = NonZeroU32::new(pkt.as_ref().len() as u32 + 4).unwrap();
                self.limit_m.until_n_ready(n).await?;
                self.limit_s.until_n_ready(n).await?;

                server_w.send(pkt.as_ref().clone().into()).await?;
            }

            anyhow::Ok(())
        };

        let writer = async move {
            while let Some(pkt) = server_r.next().await {
                let pkt = pkt?;
                remote_w.send(pkt).await?;
            }

            anyhow::Ok(())
        };

        tokio::select! {
            r = reader => r?,
            w = writer => w?,
        }

        self.remote.close().await?;
        //server_w.close().await?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub no_delay: bool,
    pub timeout: Duration,
    pub traffic_limit_min: NonZeroU32,
    pub traffic_limit_sec: NonZeroU32,
}

pub struct Proxy {
    cdc: Arc<LegacyCodec>,
    cfg: ProxyConfig,
    listen_addr: IpAddr,
    listen_port: u16,
    connector: ProxyConnector,
}

impl Proxy {
    pub fn new(
        cdc: Arc<LegacyCodec>,
        cfg: ProxyConfig,
        connector: ProxyConnector,
        listen_addr: IpAddr,
        listen_port: u16,
    ) -> Self {
        Self {
            cdc,
            cfg,
            connector,
            listen_addr,
            listen_port,
        }
    }

    pub fn handle_new_conn(
        self: Arc<Self>,
        conn: TcpStream,
        conn_holder: IpConnectionHolder,
    ) -> anyhow::Result<()> {
        let peer_addr = conn.peer_addr()?;
        // Check peer addr
        log::info!("New connection from {peer_addr}");
        tokio::spawn(async move {
            if let Err(e) = self.exec_conn(conn, conn_holder).await {
                log::error!("Error while handling connection from {peer_addr}: {e}");
            }
        });

        Ok(())
    }

    async fn exec_conn(
        self: Arc<Self>,
        conn: TcpStream,
        holder: IpConnectionHolder,
    ) -> anyhow::Result<()> {
        let addr = conn.peer_addr()?.ip();
        let t = self.cfg.timeout;
        let conn = timeout(t, self.cdc.create_server(conn)).await??;
        let server_conn = timeout(t, self.connector.connect(addr)).await??;
        ProxySession::new(server_conn, conn, &self.cfg, holder)
            .run()
            .await
    }

    pub async fn run(self: Arc<Self>, mut ip_limiter: IpLimiter<Ipv4Addr>) -> anyhow::Result<()> {
        let listener = TcpListener::bind((self.listen_addr, self.listen_port)).await?;

        let mut listener = TcpListenerStream::new(listener);
        while let Some(stream) = listener.next().await {
            let stream = stream?;
            if self.cfg.no_delay {
                stream.set_nodelay(true)?;
            }

            let addr = stream.peer_addr()?.ip();
            let IpAddr::V4(addr) = addr else {
                log::info!("Connection from {addr} blocked by ip limiter");
                continue;
            };
            let Some(conn_holder) = ip_limiter.claim_connect(&addr) else {
                log::info!("Connection from {addr} blocked by ip limiter");
                continue;
            };

            self.clone().handle_new_conn(stream, conn_holder)?;
        }

        Ok(())
    }
}
