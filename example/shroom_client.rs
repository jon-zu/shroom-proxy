use std::{
    net::{Ipv4Addr, SocketAddrV4},
    sync::Arc,
    time::Instant,
};

use futures::{future::try_join_all, SinkExt, StreamExt};
use shroom_net::{
    codec::{
        legacy::{handshake_gen::BasicHandshakeGenerator, LegacyCodec},
        ShroomCodec,
    },
    crypto::CryptoContext,
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
    let mut client = cdc.create_client(io).await?;
    let (rx, tx) = client.split();

    const PKT: [u8; 4096] = [0xFFu8; 4096];
    let chunk = pkts / chunks;
    for i in 0..chunk {
        for _ in 0..chunks {
            tx.send(&PKT).await?;
        }

        for _ in 0..chunks {
            let pkt = rx.next().await.unwrap().unwrap();
            assert_eq!(pkt.as_ref().as_ref(), PKT);
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
