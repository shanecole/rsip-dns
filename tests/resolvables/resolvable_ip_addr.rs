use rsip_dns::resolvables::*;

#[tokio::test]
async fn resolves_correctly() {
    use testing_utils::Randomize;

    let ip_addr = Randomize::random();
    let port = Randomize::random();
    let transport = Randomize::random();

    let mut resolvable = ResolvableIpAddr::new(ip_addr, port, transport);

    let target = resolvable.resolve_next().await;
    assert!(target.is_some());
    let target = target.unwrap();
    assert_eq!(target.ip_addr, ip_addr);
    assert_eq!(target.port, port);
    assert_eq!(target.transport, transport);
    assert_eq!(target.ttl, 300); // Default TTL from ResolvableIpAddr::new

    assert!(resolvable.resolve_next().await.is_none());
}

#[tokio::test]
async fn resolves_with_custom_ttl() {
    use testing_utils::Randomize;

    let ip_addr = Randomize::random();
    let port = Randomize::random();
    let transport = Randomize::random();
    let custom_ttl = 600u32;

    let mut resolvable = ResolvableIpAddr::new_with_ttl(ip_addr, port, transport, custom_ttl);

    let target = resolvable.resolve_next().await;
    assert!(target.is_some());
    let target = target.unwrap();
    assert_eq!(target.ip_addr, ip_addr);
    assert_eq!(target.port, port);
    assert_eq!(target.transport, transport);
    assert_eq!(target.ttl, custom_ttl); // Custom TTL should be preserved

    assert!(resolvable.resolve_next().await.is_none());
}
