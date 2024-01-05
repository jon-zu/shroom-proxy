use std::{
    net::{Ipv4Addr, SocketAddrV4},
    sync::Arc,
    time::Instant, ops::Deref,
};

use anyhow::Context;
use futures::{future::try_join_all, SinkExt, StreamExt};
use shroom_net::{
    Packet,
    codec::{
        legacy::{handshake_gen::BasicHandshakeGenerator, LegacyCodec},
        ShroomCodec,
    },
    CryptoContext,
};

use tokio::net::TcpStream;


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
#[tokio::main]
async fn main() {
    const ADDR: Ipv4Addr = Ipv4Addr::LOCALHOST;
    const PORT: u16 = 8484;

    let cdc = Arc::new(LegacyCodec::new(
        CryptoContext::default().into(),
        BasicHandshakeGenerator::v83(),
    ));

    let now = Instant::now();
    let p = 4;
    let pkts = 512 * 8;
    let chunks = 8;

    
    try_join_all(
        (0..p)
            .map(|_| run_shroom_client(cdc.clone(), ADDR, PORT, pkts, chunks))
    )
    .await.unwrap();
    let elapes = now.elapsed();

    let traffic = 4096 * pkts * p;

    println!("Elapsed: {:?}", elapes);
    println!(
        "Speed: {} MBit/s",
        (traffic as f64 / elapes.as_millis() as f64) * 1000.0 / 1024.0 / 1024.0 * 8.
    );
}
