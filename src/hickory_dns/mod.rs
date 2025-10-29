//! This module holds [DnsClient](crate::DnsClient) trait implementations on top of
//! [hickory-dns](https://docs.rs/hickory-resolver/0.25.2/hickory_resolver/).
//!
//! 2 clients are provided, one async built on top of
//! [TokioAsyncResolver](https://docs.rs/hickory-resolver/0.25.2/hickory_resolver/type.TokioAsyncResolver.html)
//! of `hickory-dns` and one sync built on top of [Resolver](https://docs.rs/hickory-resolver/0.25.2/hickory_resolver/struct.Resolver.html)
//! of hickory-dns. Each variant accepts the respective `hickory-dns` resolver, so you get enormous
//! freedom and `rsip-dns` shouldn't restrict you in any way.
//!
//! In more advanced scenarios, you might want to build a custom dns client that will implement
//! query caching etc.

mod async_hickory_client;
mod hickory_client;

pub use async_hickory_client::AsyncHickoryClient;
pub use hickory_client::HickoryClient;

use std::convert::{TryFrom, TryInto};

use crate::records::*;
use hickory_proto::rr::{rdata::srv::SRV, record_data::RData};

use rsip::Error;

impl TryFrom<RData> for NaptrEntry {
    type Error = Error;

    fn try_from(rdata: RData) -> Result<Self, Self::Error> {
        match rdata {
            RData::NAPTR(entry) => Ok(Self {
                order: entry.order(),
                preference: entry.preference(),
                flags: entry.flags().into(),
                services: entry.services().try_into()?,
                regexp: entry.regexp().to_vec(),
                replacement: entry.replacement().to_string().into(),
            }),
            _ => Err(Error::Unexpected("Unexpected DNS record, was expecting NAPTR".into())),
        }
    }
}

impl From<SRV> for SrvEntry {
    fn from(srv: SRV) -> Self {
        Self {
            priority: srv.priority(),
            weight: srv.weight(),
            port: srv.port().into(),
            target: srv.target().to_string().into(),
        }
    }
}
