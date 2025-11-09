use crate::{
    DnsClient, Target,
    records::SrvDomain,
    resolvables::{
        ResolvableAddrRecord, ResolvableExt, ResolvableIpAddr, ResolvableState, ResolvableVec,
    },
};
use async_trait::async_trait;

#[derive(Debug, Clone)]
pub struct ResolvableSrvRecord<C>
where
    C: DnsClient,
{
    dns_client: C,
    domain: SrvDomain,
    resolvable_addr_records: ResolvableVec<ResolvableAddrRecord<C>, Target>,
}

#[async_trait]
impl<C> ResolvableExt<Target> for ResolvableSrvRecord<C>
where
    C: DnsClient,
{
    fn state(&self) -> ResolvableState {
        self.resolvable_addr_records.state()
    }

    async fn resolve_next(&mut self) -> Option<Target> {
        if self.resolvable_addr_records.is_unset() {
            self.resolve_domain().await;
        }

        self.resolvable_addr_records.resolve_next().await
    }
}

impl<C> ResolvableSrvRecord<C>
where
    C: DnsClient,
{
    pub fn new(dns_client: C, domain: SrvDomain) -> Self {
        Self { dns_client, domain, resolvable_addr_records: Default::default() }
    }

    /// Create from a pre-fetched SrvRecord (e.g., from NAPTR ADDITIONAL section)
    /// This immediately processes the SRV entries and uses cached additional_hosts
    pub fn from_srv_record(dns_client: C, srv_record: crate::records::SrvRecord) -> Self {
        let transport = srv_record.transport();
        let mut resolvable_addr_records = Vec::new();

        // Process each SRV entry immediately
        for (domain, port) in srv_record.domains_with_ports() {
            // Check if we have additional A/AAAA records for this target
            if let Some(addr_record) = srv_record.get_additional_for_target(&domain) {
                // Use pre-fetched IP addresses from ADDITIONAL section (FAST PATH!)
                for ip_addr in &addr_record.ip_addrs {
                    resolvable_addr_records.push(ResolvableAddrRecord::from_resolvable_ip(
                        dns_client.clone(),
                        domain.clone(),
                        port,
                        transport,
                        ResolvableIpAddr::new_with_ttl(*ip_addr, port, transport, addr_record.ttl),
                    ));
                }
            } else {
                // Fall back to separate A/AAAA query (SLOW PATH)
                resolvable_addr_records.push(ResolvableAddrRecord::new(
                    dns_client.clone(),
                    domain,
                    port,
                    transport,
                ));
            }
        }

        Self {
            dns_client,
            domain: srv_record.domain,
            resolvable_addr_records: ResolvableVec::non_empty(resolvable_addr_records),
        }
    }

    async fn resolve_domain(&mut self) {
        match self.dns_client.srv_lookup(self.domain.clone()).await {
            Some(srv_record) => {
                let transport = srv_record.transport();
                let mut resolvable_addr_records = Vec::new();

                // Process each SRV entry
                for (domain, port) in srv_record.domains_with_ports() {
                    // Check if we have additional A/AAAA records for this target
                    if let Some(addr_record) = srv_record.get_additional_for_target(&domain) {
                        // Use pre-fetched IP addresses from ADDITIONAL section (FAST PATH!)
                        for ip_addr in &addr_record.ip_addrs {
                            resolvable_addr_records.push(ResolvableAddrRecord::from_resolvable_ip(
                                self.dns_client.clone(),
                                domain.clone(),
                                port,
                                transport,
                                ResolvableIpAddr::new_with_ttl(
                                    *ip_addr,
                                    port,
                                    transport,
                                    addr_record.ttl,
                                ),
                            ));
                        }
                    } else {
                        // Fall back to separate A/AAAA query (SLOW PATH)
                        resolvable_addr_records.push(ResolvableAddrRecord::new(
                            self.dns_client.clone(),
                            domain,
                            port,
                            transport,
                        ));
                    }
                }

                self.resolvable_addr_records = ResolvableVec::non_empty(resolvable_addr_records)
            }
            None => {
                self.resolvable_addr_records = ResolvableVec::empty();
            }
        }
    }
}
