use std::{
    net::IpAddr,
    num::{NonZeroU32, NonZeroUsize},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use duration_string::DurationString;
use serde::Deserialize;
use shroom_net::{
    codec::legacy::{handshake_gen::BasicHandshakeGenerator, LegacyCodec},
    crypto::CryptoContext,
};
use tokio_native_tls::native_tls::{Certificate, TlsConnector};

use crate::{
    ip_limiter::{self, IpBlacklist},
    proxy,
};

const PROXY_VERSION: u16 = 1;

fn default_timeout() -> DurationString {
    DurationString::new(Duration::from_secs(30))
}

const fn default_traffic_limit_min() -> u32 {
    2048 * 20
}

const fn default_traffic_limit_sec() -> u32 {
    2048
}

const fn v83() -> u16 {
    83
}

const fn default_ip_cache() -> usize {
    4096
}

const fn default_conn_limit() -> usize {
    12
}

const fn default_conn_limit_min() -> u32 {
    12
}

#[derive(Deserialize, Debug)]
pub struct AppConfig {
    pub server: AppServerConfig,
    pub proxy: AppProxyConfig,
    pub mappings: Vec<ProxyMapping>,
}

#[derive(Deserialize, Debug)]
pub struct ProxyMapping {
    pub from_port: u16,
    pub to_port: u16,
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
    pub traffic_limit_min: u32,
    #[serde(default = "default_traffic_limit_sec")]
    pub traffic_limit_sec: u32,
    #[serde(default = "v83")]
    pub shroom_version: u16,
    pub blacklist_file: Option<String>,
    #[serde(default = "default_ip_cache")]
    pub ip_cache: usize,
    #[serde(default = "default_conn_limit")]
    pub conn_limit: usize,
    #[serde(default = "default_conn_limit_min")]
    pub conn_limit_min: u32,
}

pub struct App {
    cfg: AppConfig,
}

impl App {
    pub fn new(cfg: AppConfig) -> Self {
        Self { cfg }
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        let server_cfg = &self.cfg.server;
        let proxy_cfg = &self.cfg.proxy;
        let cert = std::fs::read(&server_cfg.certificate)?;

        let blacklist = if let Some(blacklist_file) = &proxy_cfg.blacklist_file {
            let blacklist = std::fs::read_to_string(blacklist_file)?;
            log::info!("Loaded blacklist from {}", blacklist_file);
            IpBlacklist::from_str(&blacklist)?
        } else {
            IpBlacklist::default()
        };

        let cx = TlsConnector::builder()
            .add_root_certificate(Certificate::from_pem(&cert)?)
            .build()?;
        let cx = tokio_native_tls::TlsConnector::from(cx);

        let proxy_cfg_ = proxy::ProxyConfig {
            server_addr: server_cfg.server_addr,
            port_mappings: self
                .cfg
                .mappings
                .iter()
                .map(|m| (m.from_port, m.to_port))
                .collect(),
            proxy_id: proxy_cfg.proxy_id,
            proxy_version: PROXY_VERSION,
            tls_hostname: server_cfg.tls_hostname.clone(),
            timeout: proxy_cfg.timeout.into(),
            traffic_limit_min: std::num::NonZeroU32::new(proxy_cfg.traffic_limit_min).unwrap(),
            traffic_limit_sec: std::num::NonZeroU32::new(proxy_cfg.traffic_limit_sec).unwrap(),
        };

        let handshake_gen = BasicHandshakeGenerator::global(proxy_cfg.shroom_version);
        let cdc = LegacyCodec::new(CryptoContext::default().into(), handshake_gen);
        let proxy = Arc::new(proxy::Proxy::new(cdc, proxy_cfg_, cx));

        let limiter = ip_limiter::IpLimiter::new(
            blacklist,
            NonZeroUsize::new(proxy_cfg.ip_cache).unwrap(),
            NonZeroU32::new(proxy_cfg.conn_limit_min).unwrap(),
            proxy_cfg.conn_limit,
        );
        proxy.run(limiter).await?;

        Ok(())
    }
}
