use super::{ARecords, CustomDnsClient, CustomDnsConfig, NaptrMap, SrvMap};
use rsip::Transport;
use rsip_dns::{records::*, *};
use std::convert::TryFrom;
use testing_utils::Randomize;

#[tokio::test]
async fn ttl_from_naptr_srv_chain() {
    use Transport::*;

    let (naptr_map, srv_map, a_records) = setup_dns_state_with_custom_ttl();
    let config = CustomDnsConfig {
        naptr: naptr_map.clone().into(),
        srv: srv_map.clone().into(),
        a: a_records.clone().into(),
    };

    let dns_client: CustomDnsClient = config.into();

    let context = Context {
        secure: true,
        transport: None,
        host: "example.com".into(),
        port: None,
        dns_client: dns_client.clone(),
        supported_transports: rsip_dns::SupportedTransports::any(),
    };

    let mut lookup = Lookup::from(context);

    // Should get targets with TTL from A records (300)
    let target1 = lookup.resolve_next().await.unwrap();
    assert_eq!(target1.transport, Tls);
    assert_eq!(target1.ttl, 300);

    let target2 = lookup.resolve_next().await.unwrap();
    assert_eq!(target2.transport, Tls);
    assert_eq!(target2.ttl, 300);
}

#[tokio::test]
async fn ttl_from_domain_with_transport() {
    use Transport::*;

    let (srv_map, a_records) = setup_srv_dns_state();

    let dns_config = CustomDnsConfig {
        naptr: super::NaptrConfig::Panic,
        srv: srv_map.clone().into(),
        a: a_records.clone().into(),
    };

    let dns_client: CustomDnsClient = dns_config.into();

    let context = Context {
        secure: true,
        transport: Some(rsip::Transport::Tcp),
        host: "example.com".into(),
        port: None,
        dns_client: dns_client.clone(),
        supported_transports: rsip_dns::SupportedTransports::any(),
    };

    let mut lookup = Lookup::from(context);

    // First target from first SRV entry
    let target = lookup.resolve_next().await.unwrap();
    assert_eq!(target.transport, Tls);
    assert_eq!(target.ttl, 300);
}

#[tokio::test]
async fn ttl_from_domain_with_port() {
    let a_records = setup_a_records();

    let dns_config = CustomDnsConfig {
        naptr: super::NaptrConfig::Panic,
        srv: super::SrvConfig::Panic,
        a: a_records.clone().into(),
    };

    let dns_client: CustomDnsClient = dns_config.into();

    let uri = rsip::Uri {
        scheme: Some(rsip::Scheme::Sip),
        host_with_port: ("example.com", 5060).into(),
        ..Default::default()
    };

    let mut lookup = Lookup::from(
        Context::initialize_from(uri, dns_client.clone(), SupportedTransports::any()).unwrap(),
    );

    let target = lookup.resolve_next().await.unwrap();
    assert_eq!(target.port, 5060.into());
    assert_eq!(target.ttl, 300);
}

#[tokio::test]
async fn ttl_from_ip_address() {
    use std::net::IpAddr;

    let host_ip_addr = IpAddr::random();
    let uri = rsip::Uri {
        host_with_port: (host_ip_addr, Option::<u16>::None).into(),
        ..Default::default()
    };

    let mut lookup = Lookup::from(
        Context::initialize_from(
            uri,
            super::super::support::PanicDnsClient,
            SupportedTransports::any(),
        )
        .unwrap(),
    );

    let Target { ip_addr, port, transport, ttl } = lookup.resolve_next().await.unwrap();
    assert_eq!(ip_addr, host_ip_addr);
    assert_eq!(port, 5060.into());
    assert_eq!(transport, rsip::Transport::Udp);
    assert_eq!(ttl, 300); // Default TTL for IP address targets

    assert!(lookup.resolve_next().await.is_none());
}

fn setup_dns_state_with_custom_ttl() -> (NaptrMap, SrvMap, ARecords) {
    let mut naptr_map = NaptrMap::new();
    naptr_map.insert(
        "example.com".into(),
        vec![(
            50,
            5,
            NaptrFlags::S,
            NaptrServices::SipsD2t,
            "_sips._tcp.example.com".try_into().unwrap(),
        )],
    );

    let mut srv_map = SrvMap::new();
    srv_map.insert(
        SrvDomain::try_from("_sips._tcp.example.com").unwrap(),
        vec![(100, 5, 10000.into(), "tcp-server1.example.com".into())],
    );

    let mut a_records = ARecords::new();
    a_records
        .insert("tcp-server1.example.com".into(), vec![Randomize::random(), Randomize::random()]);

    (naptr_map, srv_map, a_records)
}

fn setup_srv_dns_state() -> (SrvMap, ARecords) {
    let mut srv_map = SrvMap::new();
    srv_map.insert(
        SrvDomain::try_from("_sips._tcp.example.com").unwrap(),
        vec![(100, 5, 10000.into(), "tcp-server1.example.com".into())],
    );

    let mut a_records = ARecords::new();
    a_records
        .insert("tcp-server1.example.com".into(), vec![Randomize::random(), Randomize::random()]);

    (srv_map, a_records)
}

fn setup_a_records() -> ARecords {
    let mut a_records = ARecords::new();
    a_records.insert("example.com".into(), vec![Randomize::random(), Randomize::random()]);
    a_records
}
