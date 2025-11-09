use super::{AddrRecord, SrvDomain};
use rsip::{Domain, Port, Transport};
use std::collections::HashMap;

/// Simple struct that holds the SRV record details (domain and srv entries)
#[derive(Debug, Clone)]
pub struct SrvRecord {
    pub entries: Vec<SrvEntry>,
    pub domain: SrvDomain,
    pub ttl: u32,
    /// Additional A/AAAA records returned in the DNS ADDITIONAL section.
    /// This enables single-query resolution when DNS server supports recursion.
    pub additional_hosts: HashMap<Domain, AddrRecord>,
}

/// Simple struct that resembles the SRV record entries
#[derive(Debug, Clone)]
pub struct SrvEntry {
    pub priority: u16,
    pub weight: u16,
    pub port: Port,
    pub target: Domain,
}

impl SrvRecord {
    /// Create a new SrvRecord without additional hosts (backward compatible)
    pub fn new(entries: Vec<SrvEntry>, domain: SrvDomain, ttl: u32) -> Self {
        Self { entries, domain, ttl, additional_hosts: HashMap::new() }
    }

    /// Create a new SrvRecord with additional hosts from DNS ADDITIONAL section
    pub fn with_additional_hosts(
        entries: Vec<SrvEntry>,
        domain: SrvDomain,
        ttl: u32,
        additional_hosts: HashMap<Domain, AddrRecord>,
    ) -> Self {
        Self { entries, domain, ttl, additional_hosts }
    }

    /// Get additional AddrRecord for a specific target domain
    pub fn get_additional_for_target(&self, target: &Domain) -> Option<&AddrRecord> {
        self.additional_hosts.get(target)
    }

    /// Check if all SRV targets have corresponding additional records
    pub fn has_complete_additionals(&self) -> bool {
        self.entries.iter().all(|entry| self.additional_hosts.contains_key(&entry.target))
    }

    /// Get coverage ratio of additional records (0.0 to 1.0)
    pub fn additional_coverage(&self) -> f64 {
        if self.entries.is_empty() {
            return 1.0;
        }
        let covered = self
            .entries
            .iter()
            .filter(|entry| self.additional_hosts.contains_key(&entry.target))
            .count();
        covered as f64 / self.entries.len() as f64
    }

    pub fn targets(&self) -> Vec<Domain> {
        self.entries.iter().map(|s| s.target.clone()).collect::<Vec<Domain>>()
    }

    pub fn domains_with_ports(&self) -> Vec<(Domain, Port)> {
        self.entries.iter().map(|s| (s.target.clone(), s.port)).collect::<Vec<_>>()
    }

    pub fn transport(&self) -> Transport {
        self.domain.transport()
    }

    pub fn sorted(mut self) -> Self {
        use std::cmp::Reverse;

        self.entries.sort_by_key(|b| Reverse(b.total_weight()));
        self
    }
}

impl SrvEntry {
    pub fn total_weight(&self) -> u16 {
        (10000 - self.priority) + self.weight
    }
}

impl IntoIterator for SrvRecord {
    type Item = SrvEntry;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

#[cfg(feature = "testing-utils")]
impl testing_utils::Randomize for SrvDomain {
    fn random() -> Self {
        use testing_utils::Randomize;

        SrvDomain {
            domain: Randomize::random(),
            protocol: Randomize::random(),
            secure: bool::random(),
        }
    }
}

#[cfg(feature = "testing-utils")]
impl testing_utils::Randomize for SrvEntry {
    fn random() -> Self {
        use testing_utils::Randomize;

        let secure = bool::random();
        let transport = match secure {
            true => Transport::Tls,
            _ => Transport::random(),
        };
        Self {
            priority: testing_utils::rand_num_from(0..10),
            weight: testing_utils::rand_num_from(0..100),
            port: Randomize::random(),
            target: format!("_sip._{}.{}", transport.to_string().to_lowercase(), Domain::random())
                .into(),
        }
    }
}

/*
#[cfg(feature = "test-utils")]
impl crate::Randomize for SrvRecord {
    fn random() -> Self {
        use crate::Randomize;

        (2..5)
            .map(|_| SrvEntry::random())
            .collect::<Vec<_>>()
            .into()
    }
}*/
