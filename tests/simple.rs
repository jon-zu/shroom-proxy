use std::{
    net::{Ipv4Addr, SocketAddrV4},
    time::Duration, sync::Arc,
};

use shroom_net::{codec::{legacy::{LegacyCodec, handshake_gen::BasicHandshakeGenerator}, ShroomCodec}, crypto::CryptoContext};
use shroom_proxy::app::{App, AppConfig, AppProxyConfig, AppServerConfig, ProxyMapping};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_native_tls::native_tls::{Identity, TlsAcceptor};

async fn run_shroom_client(cdc: Arc<LegacyCodec>, addr: Ipv4Addr, port: u16, pkts: usize) -> anyhow::Result<()> {
    let io = TcpStream::connect(SocketAddrV4::new(addr, port)).await?;
    let mut client = cdc.create_client(io).await?;

    const PKT: [u8; 4096] = [0xFFu8; 4096];
    for i in 0..pkts {
        client.send_packet(&PKT).await?;
        let pkt = client.recv_packet().await?;
        assert_eq!(pkt.as_ref().as_ref(), PKT);
        dbg!(i);
    }


    Ok(())
}



async fn serve_tls_echo(port: u16, tls: tokio_native_tls::TlsAcceptor) -> anyhow::Result<()> {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)).await?;
    loop {
        let (socket, _) = listener.accept().await?;
        let mut socket = tls.accept(socket).await?;

        tokio::spawn(async move {
            let mut handshake = [0u8; 12];
            socket.read_exact(&mut handshake).await.unwrap();

            let mut buffer = [0u8; 4096 * 2];

            loop {
                let mut ln_buf = [0u8; 4];
                socket.read_exact(&mut ln_buf).await.unwrap();
                let ln = u32::from_be_bytes(ln_buf) as usize;
                socket.read_exact(&mut buffer[..ln]).await.unwrap();

                socket.write_all(&ln_buf).await.unwrap();
                socket.write_all(&buffer[..ln]).await.unwrap();
            }
        });
    }
}

#[tokio::test]
async fn test_proxy() {
    const PROXY_PORT: u16 = 9484;
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
            traffic_limit_min: 2048 * 20000,
            traffic_limit_sec: 2048 * 300,
            shroom_version: 83,
            blacklist_file: None,
            ip_cache: 128,
            conn_limit: 12,
            conn_limit_min: 12,
        },
        mappings: vec![ProxyMapping {
            from_port: PROXY_PORT,
            to_port: SERVER_PORT,
        }],
    });

    tokio::spawn(async move {
        if let Err(err) = app.run().await {
            eprintln!("Error: {}", err);
        }
    });

    tokio::spawn(async move {
        if let Err(err) = serve_tls_echo(SERVER_PORT, ax.into()).await {
            eprintln!("Error: {}", err);
        }
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let cdc = Arc::new(LegacyCodec::new(CryptoContext::default().into(), BasicHandshakeGenerator::v83()));
    run_shroom_client(cdc.clone(), Ipv4Addr::LOCALHOST, PROXY_PORT, 50).await.unwrap();
}
