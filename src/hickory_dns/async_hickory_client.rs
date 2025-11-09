use async_trait::async_trait;
use std::{convert::TryInto, net::IpAddr};

use crate::{DnsClient, SrvDomain, records::*};
use hickory_proto::rr::record_type::RecordType;
use hickory_resolver::TokioResolver;

use rsip::{Domain, Error};

/// Simple [DnsClient] implementor built on top of `hickory-dns`. It accepts a
/// [TokioResolver](https://docs.rs/hickory-resolver/0.25.2/hickory_resolver/type.TokioResolver.html)
/// as an argument, hence refer to `hickory-dns` manual for all the configuration.
#[derive(Debug, Clone)]
pub struct AsyncHickoryClient {
    resolver: TokioResolver,
}

impl AsyncHickoryClient {
    pub fn new(resolver: TokioResolver) -> Self {
        Self { resolver }
    }
}

#[async_trait]
impl DnsClient for AsyncHickoryClient {
    async fn naptr_lookup(&self, domain: Domain) -> Option<NaptrRecord> {
        self.resolver.lookup(domain.to_string(), RecordType::NAPTR).await.ok().map(|lookup| {
            // Extract minimum TTL from all records (standard practice for RRsets)
            let ttl = lookup.record_iter().map(|record| record.ttl()).min().unwrap_or(300);

            let entries = lookup
                .into_iter()
                .filter_map(|rdata| rdata.try_into().ok())
                .collect::<Vec<NaptrEntry>>();

            NaptrRecord::new(entries, domain, ttl)
        })
    }

    async fn srv_lookup(&self, domain: SrvDomain) -> Option<SrvRecord> {
        self.resolver.lookup(domain.to_string(), RecordType::SRV).await.ok().map(|lookup| {
            // Extract minimum TTL from all SRV records (standard practice for RRsets)
            let ttl = lookup.record_iter().map(|record| record.ttl()).min().unwrap_or(300);

            let entries = lookup
                .record_iter()
                .filter_map(|record| match record.data() {
                    hickory_proto::rr::record_data::RData::SRV(srv) => Some(SrvEntry {
                        priority: srv.priority(),
                        weight: srv.weight(),
                        port: srv.port().into(),
                        target: srv.target().to_string().into(),
                    }),
                    _ => None,
                })
                .collect::<Vec<SrvEntry>>();

            SrvRecord::new(entries, domain, ttl)
        })
    }

    async fn ip_lookup(&self, domain: Domain) -> Result<AddrRecord, Error> {
        // Try A records first
        let mut ip_addrs = Vec::new();
        let mut min_ttl = u32::MAX;

        if let Ok(lookup) = self.resolver.lookup(domain.to_string(), RecordType::A).await {
            for record in lookup.record_iter() {
                min_ttl = min_ttl.min(record.ttl());
                if let hickory_proto::rr::record_data::RData::A(a) = record.data() {
                    ip_addrs.push(IpAddr::V4(a.0));
                }
            }
        }

        // Try AAAA records
        if let Ok(lookup) = self.resolver.lookup(domain.to_string(), RecordType::AAAA).await {
            for record in lookup.record_iter() {
                min_ttl = min_ttl.min(record.ttl());
                if let hickory_proto::rr::record_data::RData::AAAA(aaaa) = record.data() {
                    ip_addrs.push(IpAddr::V6(aaaa.0));
                }
            }
        }

        if ip_addrs.is_empty() {
            return Err(Error::Unexpected(format!("No A or AAAA records found for {}", domain)));
        }

        let ttl = if min_ttl == u32::MAX { 300 } else { min_ttl };

        Ok(AddrRecord { domain, ip_addrs, ttl })
    }
}
