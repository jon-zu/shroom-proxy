use std::{
    collections::HashSet,
    num::{NonZeroU32, NonZeroUsize},
    str::FromStr, sync::{atomic::AtomicUsize, Arc},
};

use anyhow::Context;
use governor::Quota;

use crate::proxy::RateLimiter;

pub trait IpAddr: std::hash::Hash + Eq + std::clone::Clone {}

impl IpAddr for std::net::Ipv4Addr {}
impl IpAddr for std::net::Ipv6Addr {}

fn parse_entry<Ip: FromStr>(line: &str) -> anyhow::Result<(Ip, usize)> {
    let (ip, count) = line
        .split_once(|c: char| c.is_ascii_whitespace())
        .context("No count")?;
    let ip = Ip::from_str(ip.trim()).map_err(|_| anyhow::format_err!("Unable to parse ip"))?;
    let count = count.trim().parse().context("Invalid count")?;
    Ok((ip, count))
}

#[derive(Debug)]
pub struct IpBlacklist<Ip>(HashSet<Ip>);

impl<Ip> Default for IpBlacklist<Ip> {
    fn default() -> Self {
        IpBlacklist(HashSet::new())
    }
}

impl<Ip: IpAddr + FromStr> FromStr for IpBlacklist<Ip> {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.lines()
            .map(|line| line.trim())
            .filter(|line| !line.starts_with('#'))
            .map(|line| parse_entry(line.trim()).map(|(ip, _)| ip))
            .collect::<Result<HashSet<_>, Self::Err>>()
            .map(|set| IpBlacklist(set))
    }
}

impl<Ip: IpAddr> IpBlacklist<Ip> {
    pub fn add_ip(&mut self, ip: Ip) {
        self.0.insert(ip);
    }

    pub fn remove_ip(&mut self, ip: Ip) {
        self.0.remove(&ip);
    }

    pub fn is_blacklisted(&self, ip: &Ip) -> bool {
        self.0.contains(ip)
    }
}

pub struct IpConnectionHolder(Arc<AtomicUsize>);

impl Drop for IpConnectionHolder {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}



#[derive(Debug)]
pub struct IpContext {
    pub minute_limit: RateLimiter,
    pub connections: Arc<AtomicUsize>,
}

impl IpContext {
    pub fn new(minute_limit: NonZeroU32) -> Self {
        IpContext {
            minute_limit: RateLimiter::direct(Quota::per_second(minute_limit)),
            connections: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn claim_connection(&mut self, conn_limit: usize) -> Option<IpConnectionHolder> {
        // TODO this may cause problems when the lru cache drops the context
        // and then the connection count may not be correct
        if self.minute_limit.check().is_err() {
            return None;
        }

        if self.connections.load(std::sync::atomic::Ordering::SeqCst) >= conn_limit {
            return None;
        }

        self.connections.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Some(IpConnectionHolder(self.connections.clone()))
    }
}

#[derive(Debug)]
pub struct IpLimiter<Ip: IpAddr> {
    blacklist: IpBlacklist<Ip>,
    connection_limits: lru::LruCache<Ip, IpContext>,
    minute_limit: NonZeroU32,
    conn_limit: usize
}

impl<Ip> IpLimiter<Ip>
where
    Ip: IpAddr,
{
    pub fn new(blacklist: IpBlacklist<Ip>, cache: NonZeroUsize, minute_limit: NonZeroU32, conn_limit: usize) -> Self {
        IpLimiter {
            blacklist,
            connection_limits: lru::LruCache::new(cache),
            minute_limit,
            conn_limit
        }
    }

    pub fn claim_connect(&mut self, ip: &Ip) -> Option<IpConnectionHolder> {
        if self.blacklist.is_blacklisted(ip) {
            return None;
        }

        let context = self
            .connection_limits
            .get_or_insert_mut(ip.clone(), || IpContext::new(self.minute_limit));
        context.claim_connection(self.conn_limit)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn test_parse() {
        let txt = std::fs::read_to_string("blacklist/ipsum.txt").unwrap();
        let blacklist: IpBlacklist<Ipv4Addr> = txt.parse().unwrap();
        assert!(blacklist.0.len() > 0);
    }
}
