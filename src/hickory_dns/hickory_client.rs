use async_trait::async_trait;
use std::{convert::TryInto, net::IpAddr, sync::Arc};

use crate::{DnsClient, SrvDomain, records::*};
use hickory_proto::{rr::record_type::RecordType, runtime::TokioRuntimeProvider};
use hickory_resolver::{Resolver, name_server::GenericConnector};

use rsip::{Domain, Error};

/// Simple [DnsClient] implementor built on top of `hickory-dns`. It accepts a
/// [Resolver](https://docs.rs/hickory-resolver/0.25.2/hickory_resolver/struct.Resolver.html)
/// as an argument, hence refer to `hickory-dns` manual for all the configuration.
#[derive(Clone)]
pub struct HickoryClient {
    resolver: Arc<Resolver<GenericConnector<TokioRuntimeProvider>>>,
}

impl HickoryClient {
    pub fn new(resolver: Resolver<GenericConnector<TokioRuntimeProvider>>) -> Self {
        Self { resolver: Arc::new(resolver) }
    }
}

#[async_trait]
impl DnsClient for HickoryClient {
    async fn naptr_lookup(&self, domain: Domain) -> Option<NaptrRecord> {
        self.resolver.lookup(domain.to_string(), RecordType::NAPTR).await.ok().map(|lookup| {
            // Extract minimum TTL from all records (standard practice for RRsets)
            let ttl = lookup.record_iter().map(|record| record.ttl()).min().unwrap_or(300);

            let entries = lookup
                .into_iter()
                .filter_map(|rdata| rdata.try_into().ok())
                .collect::<Vec<NaptrEntry>>();

            NaptrRecord { domain, entries, ttl }
        })
    }

    async fn srv_lookup(&self, domain: SrvDomain) -> Option<SrvRecord> {
        self.resolver.srv_lookup(domain.to_string()).await.ok().map(|lookup| {
            // TODO: SrvLookup doesn't expose underlying records for TTL extraction
            // Using default TTL until hickory-dns provides access to record metadata
            let ttl = 300u32;

            let entries = lookup.into_iter().map(Into::into).collect::<Vec<SrvEntry>>();

            SrvRecord { domain, entries, ttl }
        })
    }

    async fn ip_lookup(&self, domain: Domain) -> Result<AddrRecord, Error> {
        self.resolver
            .lookup_ip(domain.to_string())
            .await
            .map(|lookup| {
                // TODO: LookupIp doesn't expose underlying records for TTL extraction
                // Using default TTL until hickory-dns provides access to record metadata
                let ttl = 300u32;

                let ip_addrs = lookup.into_iter().collect::<Vec<IpAddr>>();

                AddrRecord { domain, ip_addrs, ttl }
            })
            .map_err(|e| Error::Unexpected(e.to_string()))
    }
}
