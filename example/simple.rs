use std::{
    net::{Ipv4Addr, SocketAddrV4},
    sync::Arc,
    time::{Duration, Instant}, ops::Deref
};

use anyhow::Context;
use futures::{future::try_join_all, SinkExt, StreamExt};
use shroom_net::{
    codec::{
        legacy::{handshake_gen::BasicHandshakeGenerator, LegacyCodec},
        ShroomCodec,
    },
    CryptoContext, Packet,
};
use shroom_proxy::app::{App, AppConfig, AppProxyConfig, AppServerConfig, ProxyMapping};
use tokio::net::{TcpListener, TcpStream};
use tokio_native_tls::native_tls::{Identity, TlsAcceptor};
use tokio_websockets::server;

async fn run_shroom_client(
    cdc: Arc<LegacyCodec>,
    addr: Ipv4Addr,
    port: u16,
    pkts: usize,
    chunks: usize,
) -> anyhow::Result<()> {
    let io = TcpStream::connect(SocketAddrV4::new(addr, port)).await?;
    let client = cdc.create_client(io).await?;
    let (mut tx, mut rx) = client.into_split();

    static PKT: &'static [u8; 4096] = &[0xFFu8; 4096];
    let chunk = pkts / chunks;
    for i in 0..chunk {
        for _ in 0..chunks {
            tx.send(Packet::from_static(PKT)).await?;
        }

        for _ in 0..chunks {
            let pkt = rx.next().await.context("eof")??;
            assert_eq!(pkt.deref(), PKT);
        }
        if i % 100 == 0 {
            println!("Sent: {}", i);
        }
    }

    Ok(())
}

async fn serve_websocket(tls: tokio_native_tls::TlsAcceptor, port: u16) -> anyhow::Result<()> {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)).await?;
    let srv = server::Builder::new();
    loop {
        let (socket, _) = listener.accept().await?;
        let socket = tls.accept(socket).await?;
        let mut socket = srv.accept(socket).await?;

        tokio::spawn(async move {
            while let Some(pkt) = socket.next().await {
                let pkt = pkt.unwrap();
                socket.feed(pkt).await.unwrap();
            }
        });
    }
}

#[tokio::main]
async fn main() {
    const PROXY_PORT: u16 = 9484;
    const SERVER_URI: &str  = "wss://127.0.0.1:8484/shroom";
    const SERVER_PORT: u16 = 8484;
    const HOSTNAME: &str = "shroom.server";

    let key = include_bytes!("../keys/key.pem");
    let cert = include_bytes!("../keys/cert.pem");

    let identity = Identity::from_pkcs8(&cert[..], &key[..]).unwrap();
    let ax = TlsAcceptor::builder(identity).build().unwrap();

    let mut app = App::new(AppConfig {
        server: AppServerConfig {
            certificate: "keys/cert.pem".to_string(),
            server_addr: Ipv4Addr::new(127, 0, 0, 1).into(),
            tls_hostname: HOSTNAME.to_string(),
        },
        proxy: AppProxyConfig {
            proxy_id: 1,
            timeout: Duration::from_secs(10).into(),
            traffic_limit_min: (2048 * 2000000).try_into().unwrap(),
            traffic_limit_sec: (2048 * 200000).try_into().unwrap(),
            shroom_version: 83,
            blacklist_file: None,
            ip_cache: 128.try_into().unwrap(),
            conn_limit: 12,
            conn_limit_min: 12.try_into().unwrap(),
        },
        mappings: vec![ProxyMapping {
            from_port: PROXY_PORT,
            to: SERVER_URI.parse().unwrap(),
        }],
    });

    tokio::spawn(async move {
        if let Err(err) = app.run().await {
            eprintln!("Error: {}", err);
        }
    });

    tokio::spawn(async move {
        if let Err(err) = serve_websocket(ax.into(), SERVER_PORT).await {
            eprintln!("Error: {}", err);
        }
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let cdc = Arc::new(LegacyCodec::new(
        CryptoContext::default().into(),
        BasicHandshakeGenerator::v83(),
    ));

    let now = Instant::now();
    let p = 8;
    let pkts = 512 * 16;
    let chunks = 16;

    try_join_all(
        (0..p)
            .map(|_| run_shroom_client(cdc.clone(), Ipv4Addr::LOCALHOST, PROXY_PORT, pkts, chunks)),
    )
    .await
    .unwrap();
    let elapes = now.elapsed();

    let traffic = 4096 * pkts * p;

    println!("Elapsed: {:?}", elapes);
    println!(
        "Speed: {} MBit/s",
        (traffic as f64 / elapes.as_millis() as f64) * 1000.0 / 1024.0 / 1024.0 * 8.
    );
}
