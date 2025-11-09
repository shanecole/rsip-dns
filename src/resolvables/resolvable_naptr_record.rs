use crate::{
    DnsClient, Target,
    records::NaptrFlags,
    resolvables::{ResolvableExt, ResolvableSrvRecord, ResolvableState, ResolvableVec},
};
use async_trait::async_trait;
use rsip::{Domain, Transport};
use std::convert::TryInto;

#[derive(Debug, Clone)]
pub struct ResolvableNaptrRecord<C>
where
    C: DnsClient,
{
    dns_client: C,
    domain: Domain,
    available_transports: Vec<Transport>,
    resolvable_srv_records: ResolvableVec<ResolvableSrvRecord<C>, Target>,
}

#[async_trait]
impl<C> ResolvableExt<Target> for ResolvableNaptrRecord<C>
where
    C: DnsClient,
{
    fn state(&self) -> ResolvableState {
        self.resolvable_srv_records.state()
    }

    async fn resolve_next(&mut self) -> Option<Target> {
        if self.resolvable_srv_records.is_unset() {
            self.resolve_domain().await;
        }

        self.resolvable_srv_records.resolve_next().await
    }
}

impl<C> ResolvableNaptrRecord<C>
where
    C: DnsClient,
{
    pub fn new(dns_client: C, domain: Domain, available_transports: Vec<Transport>) -> Self {
        Self {
            dns_client,
            domain,
            available_transports,
            resolvable_srv_records: Default::default(),
        }
    }

    //TODO: should probably resolve U + sip URI and A flag as well ?
    async fn resolve_domain(&mut self) {
        use crate::SrvDomain;

        let naptr_record = match self.dns_client.naptr_lookup(self.domain.clone()).await {
            Some(naptr_record) => naptr_record,
            None => {
                self.resolvable_srv_records = ResolvableVec::empty();
                return;
            }
        };

        // Check if we have cached SRV records from ADDITIONAL section
        let has_additional_srvs = !naptr_record.additional_srvs.is_empty();

        let resolvable_srv_records = naptr_record
            .iter()
            .filter(|s| match s.services.transport() {
                Some(transport) => self.available_transports.contains(&transport),
                None => false,
            })
            .filter(|s| matches!(s.flags, NaptrFlags::S))
            .filter_map(|e| {
                if let Ok(srv_domain) = TryInto::<SrvDomain>::try_into(e.clone()) {
                    // Check if we have this SRV in additional section
                    if has_additional_srvs
                        && let Some(srv_record) = naptr_record.get_additional_srv(&srv_domain)
                    {
                        // Use cached SRV record - it already has additional_hosts populated
                        // Create ResolvableSrvRecord with pre-fetched data
                        return Some(ResolvableSrvRecord::from_srv_record(
                            self.dns_client.clone(),
                            srv_record.clone(),
                        ));
                    }
                    // No cached SRV, create one that will query DNS
                    Some(ResolvableSrvRecord::new(self.dns_client.clone(), srv_domain))
                } else {
                    None
                }
            })
            .collect::<Vec<ResolvableSrvRecord<C>>>();

        self.resolvable_srv_records = ResolvableVec::non_empty(resolvable_srv_records)
    }
}
