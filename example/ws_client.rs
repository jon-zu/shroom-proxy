use std::{net::Ipv4Addr, str::FromStr, sync::Arc, time::Instant};

use anyhow::Context;
use bytes::Bytes;
use futures::{future::try_join_all, SinkExt, StreamExt};
use http::Uri;

use shroom_proxy::proxy_conn::ProxyConnector;

use tokio_native_tls::native_tls::{Certificate, TlsConnector};
use tokio_websockets::Connector;

async fn run_proxy_client(
    conn: Arc<Connector>,
    uri: Uri,
    tls_hostname: String,
    chunks: usize,
    pkts: usize,
) -> anyhow::Result<()> {
    let conn = ProxyConnector::new(conn, uri, tls_hostname);
    let mut client = conn.connect(Ipv4Addr::LOCALHOST.into()).await?;

    const PKT: [u8; 4096] = [0xFFu8; 4096];
    let bytes = Bytes::from_static(&PKT);
    let chunk = pkts / chunks;
    for i in 0..chunk {
        for _ in 0..chunks {
            client.send(bytes.clone().into()).await?;
        }

        for _ in 0..chunks {
            let pkt = client.next().await.context("no pkt")??;
            assert_eq!(pkt.as_ref(), PKT);
        }
        if i % 100 == 0 {
            println!("Sent: {}", i);
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    const SERVER_PORT: u16 = 8484;
    const HOSTNAME: &str = "shroom.server";
    let cert = include_bytes!("../keys/cert.pem");

    let cx = TlsConnector::builder()
        .add_root_certificate(Certificate::from_pem(&cert[..]).unwrap())
        .build()
        .unwrap();

    let now = Instant::now();
    let p = 1;
    let pkts = 512 * 16 * 16;
    let chunks = 16;

    let conn = Arc::new(Connector::NativeTls(cx.into()));

    try_join_all((0..p).map(|_| {
        run_proxy_client(
            conn.clone(),
            Uri::from_str(&format!("wss://127.0.0.1:{SERVER_PORT}/shroom")).unwrap(),
            HOSTNAME.to_string(),
            chunks,
            pkts,
        )
    }))
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
