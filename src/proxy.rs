use std::{
    net::{IpAddr, Ipv4Addr},
    num::NonZeroU32,
    sync::Arc,
    time::Duration,
};

use futures::{SinkExt, StreamExt};

use governor::{
    clock,
    middleware::NoOpMiddleware,
    state::{InMemoryState, NotKeyed},
    Quota,
};
use shroom_net::{
    codec::{legacy::LegacyCodec, ShroomCodec},
    ShroomConn,
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_native_tls::TlsStream;
use tokio_stream::wrappers::TcpListenerStream;
use tokio_util::{
    bytes::BufMut,
    codec::{length_delimited, Framed, LengthDelimitedCodec},
};

use crate::ip_limiter::{IpConnectionHolder, IpLimiter};

const PACKET_LEN_LIMIT: usize = 8 * 1024;

type ServerConn = Framed<TlsStream<TcpStream>, LengthDelimitedCodec>;
type RemoteConn = ShroomConn<LegacyCodec>;

pub type RateLimiter =
    governor::RateLimiter<NotKeyed, InMemoryState, clock::DefaultClock, NoOpMiddleware>;

fn server_codec() -> LengthDelimitedCodec {
    length_delimited::LengthDelimitedCodec::builder()
        .big_endian()
        .max_frame_length(PACKET_LEN_LIMIT)
        .length_field_type::<u32>()
        .new_codec()
}

pub struct ProxyConn {
    server: ServerConn,
    remote: RemoteConn,
    timeout: Duration,
    limit_s: RateLimiter,
    limit_m: RateLimiter,
    _conn_holder: IpConnectionHolder,
}

impl ProxyConn {
    pub fn new(
        server: ServerConn,
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

    pub async fn run(&mut self) -> anyhow::Result<()> {
        let (remote_r, remote_w) = self.remote.split();

        loop {
            tokio::select! {
                Some(packet) = remote_r.0.next() => {
                    let packet = packet?;

                    let n = packet.as_ref().len();
                    let n = NonZeroU32::new(n as u32).unwrap();
                    self.limit_s.until_n_ready(n).await?;
                    self.limit_m.until_n_ready(n).await?;

                    let packet = packet.as_ref().clone(); // TODO get rid off this
                    self.server.send(packet).await?;
                }
                Some(packet) = self.server.next() => {
                    let packet = packet?;
                    remote_w.0.send(&packet).await?;
                },
                _ = tokio::time::sleep(self.timeout) => {
                    return Err(anyhow::anyhow!("Timeout"));
                }
            }
        }
    }
}

pub struct ProxyConfig {
    pub server_addr: IpAddr,
    pub port_mappings: Vec<(u16, u16)>,
    pub proxy_id: u32,
    pub proxy_version: u16,
    pub tls_hostname: String,
    pub timeout: Duration,
    pub traffic_limit_min: NonZeroU32,
    pub traffic_limit_sec: NonZeroU32,
}

pub struct Proxy {
    cdc: LegacyCodec,
    cfg: ProxyConfig,
    tls: tokio_native_tls::TlsConnector,
}

impl Proxy {
    pub fn new(cdc: LegacyCodec, cfg: ProxyConfig, tls: tokio_native_tls::TlsConnector) -> Self {
        Self { cdc, cfg, tls }
    }

    async fn connect_to_server(
        self: Arc<Self>,
        to_port: u16,
        remote_addr: Ipv4Addr,
    ) -> anyhow::Result<ServerConn> {
        let cfg = &self.cfg;
        let conn = TcpStream::connect((cfg.server_addr, to_port)).await?;
        let mut conn = self.tls.connect(&cfg.tls_hostname, conn).await?;

        // 2 + 4 + 4 + 4 = 12 bytes handshake
        let mut buf = Vec::with_capacity(32);
        buf.put_u16(0xFE);
        buf.put_u32(cfg.proxy_id);
        buf.put_u16(cfg.proxy_version);
        buf.put(remote_addr.octets().as_slice());
        conn.write_all(&buf).await?;

        Ok(Framed::new(conn, server_codec()))
    }

    pub fn handle_new_conn(
        self: Arc<Self>,
        conn: TcpStream,
        to_port: u16,
        conn_holder: IpConnectionHolder,
    ) -> anyhow::Result<()> {
        let peer_addr = conn.peer_addr()?;
        // Check peer addr
        log::info!("New connection from {peer_addr}");
        tokio::spawn(async move {
            if let Err(e) = self.exec_conn(conn, to_port, conn_holder).await {
                log::error!("Error while handling connection from {peer_addr}: {e}");
            }
        });

        Ok(())
    }

    async fn exec_conn(
        self: Arc<Self>,
        conn: TcpStream,
        to_port: u16,
        holder: IpConnectionHolder,
    ) -> anyhow::Result<()> {
        let IpAddr::V4(addr) = conn.peer_addr()?.ip() else {
            return Err(anyhow::anyhow!("Ipv6 not supported"));
        };

        let t = self.cfg.timeout;

        let conn = timeout(t, self.cdc.create_server(conn)).await??;
        let server_conn = timeout(t, self.clone().connect_to_server(to_port, addr)).await??;
        ProxyConn::new(server_conn, conn, &self.cfg, holder)
            .run()
            .await
    }

    pub async fn run(
        self: Arc<Self>,
        mut ip_limiter: IpLimiter<Ipv4Addr>,
    ) -> anyhow::Result<()> {
        let first_mapping = self.cfg.port_mappings.first().unwrap();
        let listener = TcpListener::bind((
            Ipv4Addr::UNSPECIFIED,
            first_mapping.0,
        ))
        .await?;

        let mut listener = TcpListenerStream::new(listener);
        while let Some(stream) = listener.next().await {
            let stream = stream?;

            let addr = stream.peer_addr()?.ip();
            let IpAddr::V4(addr) = addr else {
                log::info!("Connection from {addr} blocked by ip limiter");
                continue;
            };
            let Some(conn_holder) = ip_limiter.claim_connect(&addr) else {
                log::info!("Connection from {addr} blocked by ip limiter");
                continue;
            };

            self.clone().handle_new_conn(stream, first_mapping.1, conn_holder)?;
        }

        Ok(())
    }
}
