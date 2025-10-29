use async_trait::async_trait;
use std::{convert::TryInto, net::IpAddr, sync::Arc};

use crate::{records::*, DnsClient, SrvDomain};
use hickory_proto::{rr::record_type::RecordType, runtime::TokioRuntimeProvider};
use hickory_resolver::{name_server::GenericConnector, Resolver};

use rsip::{Domain, Error};

/// Simple [DnsClient] implementor built on top of `hickory-dns`. It accepts a
/// [Resolver](https://docs.rs/hickory-resolver/0.25.2/hickory_resolver/struct.Resolver.html)
/// as an argument, hence refer to `hickory-dns` manual for all the configuration.
#[derive(Clone)]
pub struct TrustDnsClient {
    resolver: Arc<Resolver<GenericConnector<TokioRuntimeProvider>>>,
}

impl TrustDnsClient {
    pub fn new(resolver: Resolver<GenericConnector<TokioRuntimeProvider>>) -> Self {
        Self { resolver: Arc::new(resolver) }
    }
}

#[async_trait]
impl DnsClient for TrustDnsClient {
    async fn naptr_lookup(&self, domain: Domain) -> Option<NaptrRecord> {
        self.resolver.lookup(domain.to_string(), RecordType::NAPTR).await.ok().map(|r| {
            let entries = r
                .into_iter()
                .filter_map(|rdata| rdata.try_into().ok())
                .collect::<Vec<NaptrEntry>>();
            NaptrRecord { domain, entries }
        })
    }

    async fn srv_lookup(&self, domain: SrvDomain) -> Option<SrvRecord> {
        self.resolver.srv_lookup(domain.to_string()).await.ok().map(|r| {
            let entries = r.into_iter().map(Into::into).collect::<Vec<SrvEntry>>();
            SrvRecord { domain, entries }
        })
    }

    async fn ip_lookup(&self, domain: Domain) -> Result<AddrRecord, Error> {
        self.resolver
            .lookup_ip(domain.to_string())
            .await
            .map(|r| {
                let ip_addrs = r.into_iter().map(Into::into).collect::<Vec<IpAddr>>();
                AddrRecord { domain, ip_addrs }
            })
            .map_err(|e| Error::Unexpected(e.to_string()))
    }
}
