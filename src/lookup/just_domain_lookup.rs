//! Lazy fallback implementation for just_domain_lookup.
//!
//! This module implements a state machine that only tries fallback DNS queries
//! when primary methods fail, eliminating unnecessary queries after successful
//! NAPTR or SRV resolutions.

use crate::{
    Context, DnsClient, Target,
    records::SrvDomain,
    resolvables::{
        ResolvableAddrRecord, ResolvableExt, ResolvableNaptrRecord, ResolvableSrvRecord,
        ResolvableState,
    },
};
use async_trait::async_trait;
use rsip::{Domain, Transport};

/// State machine for just_domain_lookup that implements lazy fallback evaluation.
///
/// This prevents unnecessary DNS queries by only trying fallbacks when the
/// primary method fails to produce results.
///
/// Flow:
/// 1. Try NAPTR (which internally queries SRV for NAPTR results)
/// 2. If NAPTR produced results → Done (no fallbacks)
/// 3. If NAPTR failed → Try SRV for each supported transport
/// 4. If any SRV produced results → Done
/// 5. If all SRV failed → Try A/AAAA on base domain
#[derive(Debug, Clone)]
pub struct JustDomainLookup<C>
where
    C: DnsClient,
{
    state: JustDomainLookupState<C>,
}

#[derive(Debug, Clone)]
enum JustDomainLookupState<C>
where
    C: DnsClient,
{
    /// Trying NAPTR lookup first (primary method per RFC 3263)
    TryingNaptr {
        naptr: ResolvableNaptrRecord<C>,
        fallback_config: FallbackConfig<C>,
    },
    /// NAPTR failed, trying SRV for each supported transport
    TryingSrvFallbacks {
        srv_lookups: Vec<ResolvableSrvRecord<C>>,
        current_index: usize,
        any_produced_results: bool,
        addr_fallback: ResolvableAddrRecord<C>,
    },
    /// SRV fallbacks failed, trying A/AAAA on base domain
    TryingAddrFallback { addr: ResolvableAddrRecord<C> },
    /// All methods exhausted
    Done,
}

#[derive(Debug, Clone)]
struct FallbackConfig<C>
where
    C: DnsClient,
{
    dns_client: C,
    domain: Domain,
    available_protocols: Vec<Transport>,
    secure: bool,
    default_transport: Transport,
}

impl<C> JustDomainLookup<C>
where
    C: DnsClient,
{
    /// Create a new JustDomainLookup from a Context
    pub fn new(ctx: Context<C>) -> Self {
        let domain = match ctx.host {
            rsip::Host::Domain(ref d) => d.clone(),
            _ => panic!("JustDomainLookup requires a domain"),
        };

        let default_transport = match ctx.secure {
            true => Transport::default_secure_transport(),
            false => Transport::default_insecure_transport(),
        };

        let fallback_config = FallbackConfig {
            dns_client: ctx.dns_client.clone(),
            domain: domain.clone(),
            available_protocols: ctx.available_protocols(),
            secure: ctx.secure,
            default_transport,
        };

        let naptr =
            ResolvableNaptrRecord::new(ctx.dns_client.clone(), domain, ctx.available_transports());

        Self {
            state: JustDomainLookupState::TryingNaptr {
                naptr,
                fallback_config,
            },
        }
    }
}

#[async_trait]
impl<C> ResolvableExt<Target> for JustDomainLookup<C>
where
    C: DnsClient,
{
    fn state(&self) -> ResolvableState {
        match &self.state {
            JustDomainLookupState::TryingNaptr { naptr, .. } => naptr.state(),
            JustDomainLookupState::TryingSrvFallbacks { srv_lookups, current_index, .. } => {
                srv_lookups.get(*current_index).map(|s| s.state()).unwrap_or(ResolvableState::Empty)
            }
            JustDomainLookupState::TryingAddrFallback { addr } => addr.state(),
            JustDomainLookupState::Done => ResolvableState::Empty,
        }
    }

    async fn resolve_next(&mut self) -> Option<Target> {
        loop {
            match &mut self.state {
                JustDomainLookupState::TryingNaptr { naptr, fallback_config } => {
                    // Check state before calling resolve_next to see if initialized
                    let state_before = naptr.state();

                    match naptr.resolve_next().await {
                        Some(target) => {
                            return Some(target);
                        }
                        None => {
                            // NAPTR exhausted - check if it was initialized and produced results
                            // If state was NonEmpty before this call, NAPTR had processed results
                            // If state was Unset, NAPTR never initialized (failed)
                            let state_after = naptr.state();

                            // NAPTR succeeded if it transitioned from Unset to Empty/NonEmpty
                            // or if it was NonEmpty (had results)
                            let naptr_succeeded = !matches!(state_before, ResolvableState::Unset)
                                || !matches!(state_after, ResolvableState::Unset);

                            if naptr_succeeded && matches!(state_after, ResolvableState::Empty) {
                                // NAPTR was processed (not Unset anymore) and is now exhausted
                                // This means it succeeded and we don't need fallbacks
                                self.state = JustDomainLookupState::Done;
                                return None;
                            } else {
                                // NAPTR failed (still Unset) or never had records, try SRV fallbacks
                                let srv_lookups: Vec<ResolvableSrvRecord<C>> = fallback_config
                                    .available_protocols
                                    .iter()
                                    .map(|transport| {
                                        let srv_domain = SrvDomain {
                                            secure: fallback_config.secure,
                                            protocol: transport.protocol(),
                                            domain: fallback_config.domain.clone(),
                                        };
                                        ResolvableSrvRecord::new(
                                            fallback_config.dns_client.clone(),
                                            srv_domain,
                                        )
                                    })
                                    .collect();

                                let addr_fallback = ResolvableAddrRecord::new(
                                    fallback_config.dns_client.clone(),
                                    fallback_config.domain.clone(),
                                    fallback_config.default_transport.default_port(),
                                    fallback_config.default_transport,
                                );

                                self.state = JustDomainLookupState::TryingSrvFallbacks {
                                    srv_lookups,
                                    current_index: 0,
                                    any_produced_results: false,
                                    addr_fallback,
                                };
                                // Continue to next iteration to try SRV fallbacks
                            }
                        }
                    }
                }

                JustDomainLookupState::TryingSrvFallbacks {
                    srv_lookups,
                    current_index,
                    any_produced_results,
                    addr_fallback,
                } => {
                    // Try current SRV lookup
                    if let Some(current_srv) = srv_lookups.get_mut(*current_index) {
                        match current_srv.resolve_next().await {
                            Some(target) => {
                                *any_produced_results = true;
                                return Some(target);
                            }
                            None => {
                                // Current SRV exhausted, move to next
                                *current_index += 1;
                                // Continue to next iteration to try next SRV
                            }
                        }
                    } else {
                        // All SRV fallbacks exhausted
                        if *any_produced_results {
                            // At least one SRV worked, we're done
                            self.state = JustDomainLookupState::Done;
                            return None;
                        } else {
                            // All SRV failed, try A/AAAA fallback
                            let addr = addr_fallback.clone();
                            self.state = JustDomainLookupState::TryingAddrFallback { addr };
                            // Continue to next iteration to try A/AAAA
                        }
                    }
                }

                JustDomainLookupState::TryingAddrFallback { addr } => {
                    match addr.resolve_next().await {
                        Some(target) => return Some(target),
                        None => {
                            // A/AAAA exhausted, nothing left to try
                            self.state = JustDomainLookupState::Done;
                            return None;
                        }
                    }
                }

                JustDomainLookupState::Done => return None,
            }
        }
    }
}
