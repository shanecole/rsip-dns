use once_cell::sync::Lazy;
use rsip::{Domain, Error};
use rsip_dns::{DnsClient, records::*, resolvables::*};
use std::{collections::HashMap, net::IpAddr};

#[tokio::test]
async fn resolves_correctly() {
    let mut resolvable = ResolvableSrvRecord::new(CustomMockedDnsClient, SRV_RECORD.domain.clone());

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
        unimplemented!()
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

static SRV_RECORD: Lazy<SrvRecord> = Lazy::new(|| {
    use testing_utils::Randomize;

    SrvRecord::new(
        vec![
            SrvEntry {
                priority: 1,
                port: Randomize::random(),
                weight: 2,
                target: TARGETS.first().cloned().unwrap(),
            },
            SrvEntry {
                priority: 3,
                port: Randomize::random(),
                weight: 4,
                target: TARGETS.last().cloned().unwrap(),
            },
        ],
        Randomize::random(),
        300,
    )
});

static IP_ADDRS: Lazy<HashMap<String, Vec<IpAddr>>> = Lazy::new(|| {
    use testing_utils::Randomize;

    let mut m = HashMap::new();
    m.insert(TARGETS.first().unwrap().to_string(), vec![Randomize::random(), Randomize::random()]);
    m.insert(TARGETS.last().unwrap().to_string(), vec![Randomize::random(), Randomize::random()]);

    m
});

static TARGETS: Lazy<Vec<Domain>> = Lazy::new(|| {
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
        async fn naptr_lookup(&self, _domain: Domain) -> Option<NaptrRecord> {
            unimplemented!()
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
                600, // Custom TTL
            ))
        }
        async fn ip_lookup(&self, domain: Domain) -> Result<AddrRecord, Error> {
            Ok(AddrRecord {
                ip_addrs: vec![Randomize::random()],
                domain,
                ttl: 600, // Custom TTL
            })
        }
    }

    let mut resolvable = ResolvableSrvRecord::new(
        CustomTtlDnsClient,
        SrvDomain {
            domain: Domain::from("example.com"),
            protocol: rsip::Transport::Tcp,
            secure: false,
        },
    );

    let target = resolvable.resolve_next().await;
    assert!(target.is_some());
    assert_eq!(target.unwrap().ttl, 600); // TTL should be propagated from AddrRecord

    assert!(resolvable.resolve_next().await.is_none());
}
