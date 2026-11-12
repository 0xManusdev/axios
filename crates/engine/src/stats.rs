//! Compteurs du moteur (atomiques, sans verrou sur le chemin chaud).

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

use dashmap::DashMap;

/// Octets échangés. `up` = téléphone -> internet, `down` = internet -> téléphone.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub up_bytes: u64,
    pub down_bytes: u64,
}

#[derive(Clone, Debug, Default)]
pub struct EngineStats {
    pub total: Counters,
    /// Clé : IP du client.
    pub per_device: HashMap<Ipv4Addr, Counters>,
    pub active_tcp: usize,
    pub active_udp: usize,
    pub packets: PacketCounters,
    /// Requêtes DNS refusées par la liste de blocage (réponse NXDOMAIN).
    pub ads_blocked: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PacketCounters {
    pub fwd_tcp: u64,
    pub fwd_udp: u64,
    pub reflected_out: u64,
    pub udp_back: u64,
    pub dropped: u64,
    pub errors: u64,
}

#[derive(Default)]
struct DeviceCounters {
    up: AtomicU64,
    down: AtomicU64,
}

/// Compteurs partagés entre threads.
#[derive(Default)]
pub struct Stats {
    up: AtomicU64,
    down: AtomicU64,
    devices: DashMap<Ipv4Addr, DeviceCounters>,
    pub fwd_tcp: AtomicU64,
    pub fwd_udp: AtomicU64,
    pub reflected_out: AtomicU64,
    pub udp_back: AtomicU64,
    pub dropped: AtomicU64,
    pub errors: AtomicU64,
    pub ads_blocked: AtomicU64,
}

impl Stats {
    /// Octets téléphone -> internet.
    pub fn add_up(&self, client: Ipv4Addr, n: u64) {
        self.up.fetch_add(n, Relaxed);
        self.devices
            .entry(client)
            .or_default()
            .up
            .fetch_add(n, Relaxed);
    }

    /// Octets internet -> téléphone.
    pub fn add_down(&self, client: Ipv4Addr, n: u64) {
        self.down.fetch_add(n, Relaxed);
        self.devices
            .entry(client)
            .or_default()
            .down
            .fetch_add(n, Relaxed);
    }

    pub fn count(counter: &AtomicU64) {
        counter.fetch_add(1, Relaxed);
    }

    pub fn snapshot(&self, active_tcp: usize, active_udp: usize) -> EngineStats {
        EngineStats {
            total: Counters {
                up_bytes: self.up.load(Relaxed),
                down_bytes: self.down.load(Relaxed),
            },
            per_device: self
                .devices
                .iter()
                .map(|e| {
                    (
                        *e.key(),
                        Counters {
                            up_bytes: e.value().up.load(Relaxed),
                            down_bytes: e.value().down.load(Relaxed),
                        },
                    )
                })
                .collect(),
            active_tcp,
            active_udp,
            packets: PacketCounters {
                fwd_tcp: self.fwd_tcp.load(Relaxed),
                fwd_udp: self.fwd_udp.load(Relaxed),
                reflected_out: self.reflected_out.load(Relaxed),
                udp_back: self.udp_back.load(Relaxed),
                dropped: self.dropped.load(Relaxed),
                errors: self.errors.load(Relaxed),
            },
            ads_blocked: self.ads_blocked.load(Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totals_and_per_device() {
        let s = Stats::default();
        let a = Ipv4Addr::new(192, 168, 137, 2);
        let b = Ipv4Addr::new(192, 168, 137, 3);
        s.add_up(a, 100);
        s.add_down(a, 400);
        s.add_up(b, 5);
        Stats::count(&s.dropped);
        Stats::count(&s.dropped);
        Stats::count(&s.ads_blocked);
        let snap = s.snapshot(3, 4);
        assert_eq!(
            snap.total,
            Counters {
                up_bytes: 105,
                down_bytes: 400
            }
        );
        assert_eq!(
            snap.per_device[&a],
            Counters {
                up_bytes: 100,
                down_bytes: 400
            }
        );
        assert_eq!(
            snap.per_device[&b],
            Counters {
                up_bytes: 5,
                down_bytes: 0
            }
        );
        assert_eq!((snap.active_tcp, snap.active_udp), (3, 4));
        assert_eq!(snap.packets.dropped, 2);
        assert_eq!(snap.ads_blocked, 1);
    }
}
