use once_cell::sync::Lazy;
use rsip::{Domain, Error, Transport};
use rsip_dns::{DnsClient, records::*, resolvables::*};
use std::convert::TryInto;
use std::{collections::HashMap, net::IpAddr};

#[tokio::test]
async fn resolves_correctly() {
    let mut resolvable = ResolvableNaptrRecord::new(
        CustomMockedDnsClient,
        NAPTR_RECORD.domain.clone(),
        Transport::all().to_vec(),
    );

    let target1 = resolvable.resolve_next().await;
    assert_eq!(
        target1.as_ref().map(|t| t.ip_addr),
        IP_ADDRS
            .get(&SRV_RECORD.entries.first().unwrap().clone().target.to_string())
            .unwrap()
            .first()
            .cloned()
    );
    assert_eq!(target1.unwrap().ttl, 300);

    let target2 = resolvable.resolve_next().await;
    assert_eq!(
        target2.as_ref().map(|t| t.ip_addr),
        IP_ADDRS
            .get(&SRV_RECORD.entries.first().unwrap().clone().target.to_string())
            .unwrap()
            .last()
            .cloned()
    );
    assert_eq!(target2.unwrap().ttl, 300);

    let target3 = resolvable.resolve_next().await;
    assert_eq!(
        target3.as_ref().map(|t| t.ip_addr),
        IP_ADDRS
            .get(&SRV_RECORD.entries.last().unwrap().clone().target.to_string())
            .unwrap()
            .first()
            .cloned()
    );
    assert_eq!(target3.unwrap().ttl, 300);

    let target4 = resolvable.resolve_next().await;
    assert_eq!(
        target4.as_ref().map(|t| t.ip_addr),
        IP_ADDRS
            .get(&SRV_RECORD.entries.last().unwrap().clone().target.to_string())
            .unwrap()
            .last()
            .cloned()
    );
    assert_eq!(target4.unwrap().ttl, 300);
    assert!(resolvable.resolve_next().await.is_none());
}

#[derive(Debug, Clone, Default)]
pub struct CustomMockedDnsClient;

#[async_trait::async_trait]
impl DnsClient for CustomMockedDnsClient {
    async fn naptr_lookup(&self, _domain: Domain) -> Option<NaptrRecord> {
        Some(NAPTR_RECORD.clone())
    }
    async fn srv_lookup(&self, _domain: SrvDomain) -> Option<SrvRecord> {
        Some(SRV_RECORD.clone())
    }
    async fn ip_lookup(&self, domain: Domain) -> Result<AddrRecord, Error> {
        Ok(AddrRecord {
            ip_addrs: IP_ADDRS.get(&domain.to_string()).unwrap().clone(),
            domain,
            ttl: 300,
        })
    }
}

static DOMAIN: Lazy<Domain> = Lazy::new(|| Domain::from("example.com"));

static NAPTR_RECORD: Lazy<NaptrRecord> = Lazy::new(|| {
    //use testing_utils::Randomize;

    NaptrRecord {
        entries: vec![NaptrEntry {
            order: 50,
            preference: 50,
            flags: NaptrFlags::S,
            services: NaptrServices::SipD2t,
            regexp: vec![],
            replacement: "_sips._tcp.example.com.".into(),
        }],
        domain: DOMAIN.clone(),
        ttl: 300,
        additional_srvs: std::collections::HashMap::new(),
    }
});

static SRV_RECORD: Lazy<SrvRecord> = Lazy::new(|| {
    use testing_utils::Randomize;

    SrvRecord::new(
        vec![
            SrvEntry {
                priority: 1,
                port: Randomize::random(),
                weight: 2,
                target: SRV_TARGETS.first().cloned().unwrap(),
            },
            SrvEntry {
                priority: 3,
                port: Randomize::random(),
                weight: 4,
                target: SRV_TARGETS.last().cloned().unwrap(),
            },
        ],
        NAPTR_RECORD.entries.first().unwrap().clone().try_into().unwrap(),
        300,
    )
});

static IP_ADDRS: Lazy<HashMap<String, Vec<IpAddr>>> = Lazy::new(|| {
    use testing_utils::Randomize;

    let mut m = HashMap::new();
    m.insert(
        SRV_TARGETS.first().unwrap().to_string(),
        vec![Randomize::random(), Randomize::random()],
    );
    m.insert(
        SRV_TARGETS.last().unwrap().to_string(),
        vec![Randomize::random(), Randomize::random()],
    );

    m
});

static SRV_TARGETS: Lazy<Vec<Domain>> = Lazy::new(|| {
    use testing_utils::Randomize;

    vec![Randomize::random(), Randomize::random()]
});

#[tokio::test]
async fn resolves_with_custom_ttl() {
    use testing_utils::Randomize;

    #[derive(Debug, Clone)]
    struct CustomTtlDnsClient;

    #[async_trait::async_trait]
    impl DnsClient for CustomTtlDnsClient {
        async fn naptr_lookup(&self, domain: Domain) -> Option<NaptrRecord> {
            Some(NaptrRecord {
                entries: vec![NaptrEntry {
                    order: 50,
                    preference: 50,
                    flags: NaptrFlags::S,
                    services: NaptrServices::SipD2t,
                    regexp: vec![],
                    replacement: "_sips._tcp.example.com.".into(),
                }],
                domain: domain.clone(),
                ttl: 300,
                additional_srvs: std::collections::HashMap::new(),
            })
        }
        async fn srv_lookup(&self, domain: SrvDomain) -> Option<SrvRecord> {
            Some(SrvRecord::new(
                vec![SrvEntry {
                    priority: 1,
                    port: Randomize::random(),
                    weight: 2,
                    target: Domain::from("target1.example.com"),
                }],
                domain,
                450, // Different TTL for SRV
            ))
        }
        async fn ip_lookup(&self, domain: Domain) -> Result<AddrRecord, Error> {
            Ok(AddrRecord {
                ip_addrs: vec![Randomize::random()],
                domain,
                ttl: 360, // Different TTL for A record - this should be the one used
            })
        }
    }

    let mut resolvable = ResolvableNaptrRecord::new(
        CustomTtlDnsClient,
        Domain::from("example.com"),
        vec![Transport::Tcp],
    );

    let target = resolvable.resolve_next().await;
    assert!(target.is_some());
    // TTL should be propagated from the final AddrRecord lookup
    assert_eq!(target.unwrap().ttl, 360);

    assert!(resolvable.resolve_next().await.is_none());
}
