//! Recursive DNS client implementation using hickory-proto for direct message access.
//!
//! This client can access the ADDITIONAL section of DNS responses, enabling
//! single-query resolution of SRV records with their corresponding A/AAAA records.

use async_trait::async_trait;
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use rsip::{Domain, Error};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;
use tokio::net::UdpSocket;

use crate::{records::*, DnsClient, SrvDomain};

/// Recursive DNS client that uses hickory-proto directly to access
/// the ADDITIONAL section of DNS responses.
///
/// This enables dramatic query reduction (up to 97%) by retrieving
/// A/AAAA records alongside SRV records in a single query.
#[derive(Debug, Clone)]
pub struct RecursiveHickoryClient {
    name_server: SocketAddr,
    timeout: Duration,
}

impl RecursiveHickoryClient {
    /// Create a new RecursiveHickoryClient with default timeout (5 seconds)
    pub fn new(name_server: SocketAddr) -> Self {
        Self { name_server, timeout: Duration::from_secs(5) }
    }

    /// Create a new RecursiveHickoryClient with custom timeout
    pub fn with_timeout(name_server: SocketAddr, timeout: Duration) -> Self {
        Self { name_server, timeout }
    }

    /// Send a DNS query and return the full response message
    async fn query(
        &self,
        name: Name,
        record_type: RecordType,
    ) -> Result<Message, Error> {
        // Create UDP socket
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| Error::Unexpected(format!("Failed to bind UDP socket: {}", e)))?;

        socket
            .connect(self.name_server)
            .await
            .map_err(|e| Error::Unexpected(format!("Failed to connect to DNS server: {}", e)))?;

        // Build DNS query message
        let mut message = Message::new();
        message.set_id(rand::random());
        message.set_recursion_desired(true); // Enable recursion for additional records
        message.set_op_code(hickory_proto::op::OpCode::Query);
        message.add_query(Query::query(name, record_type));

        // Serialize and send
        let query_bytes = message
            .to_vec()
            .map_err(|e| Error::Unexpected(format!("Failed to serialize DNS query: {}", e)))?;

        socket
            .send(&query_bytes)
            .await
            .map_err(|e| Error::Unexpected(format!("Failed to send DNS query: {}", e)))?;

        // Receive response with timeout
        let mut response_buf = vec![0u8; 4096];
        let len = tokio::time::timeout(self.timeout, socket.recv(&mut response_buf))
            .await
            .map_err(|_| Error::Unexpected("DNS query timeout".to_string()))?
            .map_err(|e| Error::Unexpected(format!("Failed to receive DNS response: {}", e)))?;

        // Parse response
        let response = Message::from_vec(&response_buf[..len])
            .map_err(|e| Error::Unexpected(format!("Failed to parse DNS response: {}", e)))?;

        // Check response code
        if response.response_code() != hickory_proto::op::ResponseCode::NoError {
            return Err(Error::Unexpected(format!(
                "DNS query failed with response code: {:?}",
                response.response_code()
            )));
        }

        Ok(response)
    }

    /// Parse A/AAAA records from ADDITIONAL section into AddrRecord map
    fn parse_additional_hosts(&self, message: &Message) -> HashMap<Domain, AddrRecord> {
        let mut host_map: HashMap<Domain, Vec<(IpAddr, u32)>> = HashMap::new();

        // Collect all A and AAAA records from additional section
        for record in message.additionals() {
            let domain: Domain = record.name().to_string().into();
            let ttl = record.ttl();

            match record.data() {
                RData::A(a) => {
                    host_map
                        .entry(domain.clone())
                        .or_default()
                        .push((IpAddr::V4(a.0), ttl));
                }
                RData::AAAA(aaaa) => {
                    host_map
                        .entry(domain.clone())
                        .or_default()
                        .push((IpAddr::V6(aaaa.0), ttl));
                }
                _ => {}
            }
        }

        // Convert to AddrRecord map with minimum TTL per domain
        host_map
            .into_iter()
            .map(|(domain, addrs_with_ttl)| {
                let min_ttl = addrs_with_ttl.iter().map(|(_, ttl)| *ttl).min().unwrap_or(300);
                let ip_addrs = addrs_with_ttl.into_iter().map(|(ip, _)| ip).collect();
                (domain.clone(), AddrRecord { domain, ip_addrs, ttl: min_ttl })
            })
            .collect()
    }

    /// Calculate minimum TTL from a set of records
    fn calculate_min_ttl(&self, records: &[&hickory_proto::rr::Record]) -> u32 {
        records.iter().map(|r| r.ttl()).min().unwrap_or(300)
    }
}

#[async_trait]
impl DnsClient for RecursiveHickoryClient {
    async fn naptr_lookup(&self, domain: Domain) -> Option<NaptrRecord> {
        let name = Name::from_str(&domain.to_string()).ok()?;
        let response = self.query(name, RecordType::NAPTR).await.ok()?;

        // Extract NAPTR records from ANSWER section
        let entries: Vec<NaptrEntry> = response
            .answers()
            .iter()
            .filter_map(|record| {
                if let RData::NAPTR(naptr) = record.data() {
                    let flags = match String::from_utf8(naptr.flags().to_vec()) {
                        Ok(s) if s.eq_ignore_ascii_case("s") => NaptrFlags::S,
                        Ok(s) if s.eq_ignore_ascii_case("a") => NaptrFlags::A,
                        Ok(s) if s.eq_ignore_ascii_case("u") => NaptrFlags::U,
                        Ok(s) if s.eq_ignore_ascii_case("p") => NaptrFlags::P,
                        _ => NaptrFlags::Other(naptr.flags().to_vec()),
                    };

                    let services = match String::from_utf8(naptr.services().to_vec()) {
                        Ok(s) if s.eq_ignore_ascii_case("sip+d2t") => NaptrServices::SipD2t,
                        Ok(s) if s.eq_ignore_ascii_case("sip+d2u") => NaptrServices::SipD2u,
                        Ok(s) if s.eq_ignore_ascii_case("sip+d2s") => NaptrServices::SipD2s,
                        Ok(s) if s.eq_ignore_ascii_case("sip+d2w") => NaptrServices::SipD2w,
                        Ok(s) if s.eq_ignore_ascii_case("sips+d2t") => NaptrServices::SipsD2t,
                        Ok(s) if s.eq_ignore_ascii_case("sips+d2u") => NaptrServices::SipsD2u,
                        Ok(s) if s.eq_ignore_ascii_case("sips+d2s") => NaptrServices::SipsD2s,
                        Ok(s) if s.eq_ignore_ascii_case("sips+d2w") => NaptrServices::SipsD2w,
                        Ok(s) => NaptrServices::Other(s),
                        Err(_) => NaptrServices::Other(
                            String::from_utf8_lossy(naptr.services()).to_string(),
                        ),
                    };

                    Some(NaptrEntry {
                        order: naptr.order(),
                        preference: naptr.preference(),
                        flags,
                        services,
                        regexp: naptr.regexp().to_vec(),
                        replacement: naptr.replacement().to_string().into(),
                    })
                } else {
                    None
                }
            })
            .collect();

        if entries.is_empty() {
            return None;
        }

        let ttl = self.calculate_min_ttl(&response.answers().iter().collect::<Vec<_>>());

        // Parse SRV records from ADDITIONAL section
        let mut srv_map: HashMap<String, (SrvDomain, Vec<SrvEntry>, u32)> = HashMap::new();
        for record in response.additionals() {
            if let RData::SRV(srv) = record.data() {
                let srv_name = record.name().to_string();
                if let Ok(srv_domain) = SrvDomain::try_from(srv_name.as_str()) {
                    let entry = SrvEntry {
                        priority: srv.priority(),
                        weight: srv.weight(),
                        port: srv.port().into(),
                        target: srv.target().to_string().into(),
                    };

                    srv_map
                        .entry(srv_name.clone())
                        .or_insert_with(|| (srv_domain, Vec::new(), record.ttl()))
                        .1
                        .push(entry);
                }
            }
        }

        // Parse A/AAAA records from ADDITIONAL section
        let additional_hosts = self.parse_additional_hosts(&response);

        // Build SrvRecord objects with their additional hosts
        let additional_srvs: HashMap<SrvDomain, SrvRecord> = srv_map
            .into_iter()
            .map(|(_, (srv_domain, entries, srv_ttl))| {
                // Filter additional_hosts to only include targets from this SRV
                let srv_additional_hosts: HashMap<Domain, AddrRecord> = entries
                    .iter()
                    .filter_map(|entry| {
                        additional_hosts
                            .get(&entry.target)
                            .map(|addr| (entry.target.clone(), addr.clone()))
                    })
                    .collect();

                let srv_record = SrvRecord::with_additional_hosts(
                    entries,
                    srv_domain.clone(),
                    srv_ttl,
                    srv_additional_hosts,
                );

                (srv_domain, srv_record)
            })
            .collect();

        Some(NaptrRecord::with_additional_srvs(entries, domain, ttl, additional_srvs))
    }

    async fn srv_lookup(&self, srv_domain: SrvDomain) -> Option<SrvRecord> {
        let name = Name::from_str(&srv_domain.to_string()).ok()?;
        let response = self.query(name, RecordType::SRV).await.ok()?;

        // Extract SRV records from ANSWER section
        let entries: Vec<SrvEntry> = response
            .answers()
            .iter()
            .filter_map(|record| {
                if let RData::SRV(srv) = record.data() {
                    Some(SrvEntry {
                        priority: srv.priority(),
                        weight: srv.weight(),
                        port: srv.port().into(),
                        target: srv.target().to_string().into(),
                    })
                } else {
                    None
                }
            })
            .collect();

        if entries.is_empty() {
            return None;
        }

        let ttl = self.calculate_min_ttl(&response.answers().iter().collect::<Vec<_>>());

        // Parse A/AAAA records from ADDITIONAL section
        let additional_hosts = self.parse_additional_hosts(&response);

        Some(SrvRecord::with_additional_hosts(entries, srv_domain, ttl, additional_hosts))
    }

    async fn ip_lookup(&self, domain: Domain) -> Result<AddrRecord, Error> {
        let name = Name::from_str(&domain.to_string())
            .map_err(|e| Error::Unexpected(format!("Invalid domain name: {}", e)))?;

        let mut ip_addrs = Vec::new();
        let mut min_ttl = u32::MAX;

        // Try A records first
        if let Ok(response) = self.query(name.clone(), RecordType::A).await {
            for record in response.answers() {
                if let RData::A(a) = record.data() {
                    ip_addrs.push(IpAddr::V4(a.0));
                    min_ttl = min_ttl.min(record.ttl());
                }
            }
        }

        // Try AAAA records
        if let Ok(response) = self.query(name, RecordType::AAAA).await {
            for record in response.answers() {
                if let RData::AAAA(aaaa) = record.data() {
                    ip_addrs.push(IpAddr::V6(aaaa.0));
                    min_ttl = min_ttl.min(record.ttl());
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
