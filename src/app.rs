use std::{
    net::{IpAddr, Ipv4Addr},
    num::NonZeroUsize,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use duration_string::DurationString;
use futures::future::try_join_all;
use http::Uri;
use serde::Deserialize;
use shroom_net::{
    codec::legacy::{handshake_gen::BasicHandshakeGenerator, LegacyCodec},
    crypto::CryptoContext,
};
use tokio_native_tls::native_tls::{Certificate, TlsConnector};
use tokio_websockets::Connector;

use crate::{
    ip_limiter::{self, IpBlacklist},
    proxy,
    proxy_conn::ProxyConnector,
};


const fn nonzu(v: usize) -> NonZeroUsize {
    if let Some(v) = NonZeroUsize::new(v) {
        v
    } else {
        panic!("Expected non-zero usize")
    }
}

fn default_timeout() -> DurationString {
    DurationString::new(Duration::from_secs(30))
}

const fn default_traffic_limit_min() -> NonZeroUsize {
    nonzu(2048 * 20)
}

const fn default_traffic_limit_sec() -> NonZeroUsize {
    nonzu(2048 * 20)
}

const fn v83() -> u16 {
    83
}

const fn default_ip_cache() -> NonZeroUsize {
    nonzu(4096)
}

const fn default_conn_limit() -> usize {
    12
}

const fn default_conn_limit_min() -> NonZeroUsize {
    nonzu(12)
}

#[derive(Deserialize, Debug)]
pub struct AppConfig {
    pub server: AppServerConfig,
    pub proxy: AppProxyConfig,
    pub mappings: Vec<ProxyMapping>,
}

#[derive(Debug)]
pub struct ConfigUri(pub Uri);

impl<'de> Deserialize<'de> for ConfigUri {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map(ConfigUri)
            .map_err(serde::de::Error::custom)
    }
}

impl FromStr for ConfigUri {
    type Err = http::uri::InvalidUri;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(ConfigUri(Uri::from_str(s)?))
    }
}

#[derive(Deserialize, Debug)]
pub struct ProxyMapping {
    pub from_port: u16,
    pub to: ConfigUri,
}

#[derive(Deserialize, Debug)]
pub struct AppServerConfig {
    pub certificate: String,
    pub server_addr: IpAddr,
    pub tls_hostname: String,
}

#[derive(Deserialize, Debug)]
pub struct AppProxyConfig {
    pub proxy_id: u32,
    #[serde(default = "default_timeout")]
    pub timeout: DurationString,
    #[serde(default = "default_traffic_limit_min")]
    pub traffic_limit_min: NonZeroUsize,
    #[serde(default = "default_traffic_limit_sec")]
    pub traffic_limit_sec: NonZeroUsize,
    #[serde(default = "v83")]
    pub shroom_version: u16,
    pub blacklist_file: Option<String>,
    #[serde(default = "default_ip_cache")]
    pub ip_cache: NonZeroUsize,
    #[serde(default = "default_conn_limit")]
    pub conn_limit: usize,
    #[serde(default = "default_conn_limit_min")]
    pub conn_limit_min: NonZeroUsize,
}

pub struct App {
    cfg: AppConfig,
}

impl App {
    pub fn new(cfg: AppConfig) -> Self {
        Self { cfg }
    }

    fn connector(&self) -> anyhow::Result<Connector> {
        let cert = std::fs::read(&self.cfg.server.certificate)?;
        let cx = TlsConnector::builder()
            .add_root_certificate(Certificate::from_pem(&cert)?)
            .build()?;
        Ok(Connector::NativeTls(cx.into()))
    }

    fn codec(&self) -> LegacyCodec {
        LegacyCodec::new(
            CryptoContext::default().into(),
            BasicHandshakeGenerator::global(self.cfg.proxy.shroom_version),
        )
    }

    fn blacklist(&self) -> IpBlacklist<Ipv4Addr> {
        if let Some(blacklist_file) = &self.cfg.proxy.blacklist_file {
            let blacklist = std::fs::read_to_string(blacklist_file).unwrap();
            log::info!("Loaded blacklist from {}", blacklist_file);
            IpBlacklist::from_str(&blacklist).unwrap()
        } else {
            IpBlacklist::default()
        }
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        let server_cfg = &self.cfg.server;
        let proxy_cfg = &self.cfg.proxy;

        if server_cfg.server_addr.is_ipv6() {
            log::error!("IPv6 is not supported");
            return Ok(());
        }

        let blacklist = Arc::new(self.blacklist());
        let connector = Arc::new(self.connector()?);
        let cdc = Arc::new(self.codec());

        let proxies = self
            .cfg
            .mappings
            .iter()
            .map(|mapping| {
                let proxy_connector = ProxyConnector::new(
                    connector.clone(),
                    mapping.to.0.clone(),
                    server_cfg.tls_hostname.clone(),
                );

                let proxy_cfg = proxy::ProxyConfig {
                    timeout: proxy_cfg.timeout.into(),
                    traffic_limit_min: proxy_cfg.traffic_limit_min.try_into().unwrap(),
                    traffic_limit_sec: proxy_cfg.traffic_limit_sec.try_into().unwrap(),
                    no_delay: true,
                };

                Arc::new(proxy::Proxy::new(
                    cdc.clone(),
                    proxy_cfg,
                    proxy_connector,
                    server_cfg.server_addr,
                    mapping.from_port,
                ))
            })
            .collect::<Vec<_>>();

        try_join_all(
            proxies
                .iter()
                .map(|proxy| proxy.clone().run(ip_limiter::IpLimiter::new(
                    blacklist.clone(),
                    proxy_cfg.ip_cache,
                    proxy_cfg.conn_limit_min.try_into().unwrap(),
                    proxy_cfg.conn_limit,
                ))),
        ).await.unwrap();

        Ok(())
    }
}
