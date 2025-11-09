use crate::{
    DnsClient, Target,
    resolvables::{ResolvableExt, ResolvableIpAddr, ResolvableState, ResolvableVec},
};
use async_trait::async_trait;
use rsip::{Domain, Port, Transport};

#[derive(Debug, Clone)]
pub struct ResolvableAddrRecord<C>
where
    C: DnsClient,
{
    dns_client: C,
    domain: Domain,
    port: Port,
    transport: Transport,
    resolvable_ip_addrs: ResolvableVec<ResolvableIpAddr, Target>,
}

#[async_trait]
impl<C> ResolvableExt<Target> for ResolvableAddrRecord<C>
where
    C: DnsClient,
{
    fn state(&self) -> ResolvableState {
        self.resolvable_ip_addrs.state()
    }

    async fn resolve_next(&mut self) -> Option<Target> {
        if self.resolvable_ip_addrs.is_unset() {
            self.resolve_domain().await;
        }

        self.resolvable_ip_addrs.resolve_next().await
    }
}

impl<C> ResolvableAddrRecord<C>
where
    C: DnsClient,
{
    pub fn new(dns_client: C, domain: Domain, port: Port, transport: Transport) -> Self {
        Self { dns_client, domain, port, transport, resolvable_ip_addrs: Default::default() }
    }

    /// Create a ResolvableAddrRecord from a pre-resolved ResolvableIpAddr.
    /// This is used when we have IP addresses from the DNS ADDITIONAL section.
    pub fn from_resolvable_ip(
        dns_client: C,
        domain: Domain,
        port: Port,
        transport: Transport,
        resolvable_ip: ResolvableIpAddr,
    ) -> Self {
        Self {
            dns_client,
            domain,
            port,
            transport,
            resolvable_ip_addrs: ResolvableVec::non_empty(vec![resolvable_ip]),
        }
    }

    async fn resolve_domain(&mut self) {
        match self.dns_client.ip_lookup(self.domain.clone()).await {
            Ok(a_record) => {
                let ttl = a_record.ttl;
                let resolvable_ip_addrs = a_record
                    .ip_addrs
                    .into_iter()
                    .map(|ip_addr| {
                        ResolvableIpAddr::new_with_ttl(ip_addr, self.port, self.transport, ttl)
                    })
                    .collect::<Vec<_>>();
                self.resolvable_ip_addrs = ResolvableVec::non_empty(resolvable_ip_addrs)
            }
            Err(_) => {
                self.resolvable_ip_addrs = ResolvableVec::empty();
            }
        }
    }
}
