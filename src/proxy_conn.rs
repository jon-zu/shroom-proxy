use std::{net::IpAddr, ops::Deref, sync::Arc};

use bytes::Bytes;
use futures::{Sink, SinkExt, Stream, StreamExt};
use http::{HeaderName, Uri};
use shroom_net::Packet;
use tokio::net::TcpStream;
use tokio_websockets::{
    client::{self},
    Connector, MaybeTlsStream, Message, Payload, WebSocketStream,
};

#[allow(clippy::declare_interior_mutable_const)]
const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
#[allow(clippy::declare_interior_mutable_const)]
const X_PROXY_VERSION: HeaderName = HeaderName::from_static("x-shroom-proxy-version");

pub const PROXY_VESION: u32 = 1;

pub struct ProxyConnector {
    connector: Arc<Connector>,
    uri: Uri,
    tls_hostname: String,
}

impl ProxyConnector {
    pub fn new(connector: Arc<Connector>, uri: Uri, tls_hostname: String) -> Self {
        Self {
            connector,
            tls_hostname,
            uri,
        }
    }

    pub async fn connect(&self, remote_addr: IpAddr) -> anyhow::Result<ProxyConn> {
        let (conn, _) = client::Builder::from_uri(self.uri.clone())
            .connector(&self.connector)
            .add_header(X_FORWARDED_FOR, remote_addr.to_string().try_into().unwrap())
            .add_header(X_PROXY_VERSION, PROXY_VESION.into())
            .tls_hostname(self.tls_hostname.clone())
            .connect()
            .await?;

        Ok(ProxyConn(conn))
    }
}

pub struct ProxyConn(WebSocketStream<MaybeTlsStream<TcpStream>>);

pub struct ProxyPacket(Payload);

impl TryFrom<Message> for ProxyPacket {
    type Error = tokio_websockets::Error;

    fn try_from(value: Message) -> Result<Self, Self::Error> {
        if !value.is_binary() {
            return Err(tokio_websockets::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Expected binary data",
            )));
        }
        Ok(Self(value.into_payload()))
    }
}

impl From<Packet> for ProxyPacket {
    fn from(value: Packet) -> Self {
        Self(Payload::from(value.as_bytes().clone()))
    }
}

impl From<Bytes> for ProxyPacket {
    fn from(value: Bytes) -> Self {
        Self(Payload::from(value))
    }
}

impl Deref for ProxyPacket {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.0.deref()
    }
}

impl AsRef<[u8]> for ProxyPacket {
    // TODO port shroom_net packet to be like websocket's payload
    fn as_ref(&self) -> &[u8] {
        self.0.deref()
    }
}

impl Sink<ProxyPacket> for ProxyConn {
    type Error = tokio_websockets::Error;

    fn poll_ready(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.as_mut().0.poll_ready_unpin(cx)
    }

    fn start_send(
        mut self: std::pin::Pin<&mut Self>,
        item: ProxyPacket,
    ) -> Result<(), Self::Error> {
        self.as_mut().0.start_send_unpin(Message::binary(item.0))
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.as_mut().0.poll_flush_unpin(cx)
    }

    fn poll_close(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.as_mut().0.poll_close_unpin(cx)
    }
}

impl Stream for ProxyConn {
    type Item = Result<ProxyPacket, tokio_websockets::Error>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.get_mut()
            .0
            .poll_next_unpin(cx)
            .map(|r| r.map(|m| m.and_then(ProxyPacket::try_from)))
    }
}
