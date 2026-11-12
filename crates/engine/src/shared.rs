//! État partagé entre les threads WinDivert et les tâches tokio.

use std::io;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU16, AtomicU32, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::{Duration, Instant};

use tokio::sync::watch;

use crate::ffi::{Address, Handle};
use crate::nat::TcpNat;
use crate::policy::Policy;
use crate::ratelimit::{Direction, RateLimiter};
use crate::stats::Stats;
use crate::subnet::Subnet;
use crate::udp::UdpTable;

/// Destination des paquets fabriqués ou réécrits. Abstrait le handle WinDivert d'injection
/// pour pouvoir tester la logique sans pilote.
pub trait PacketSink: Send + Sync {
    /// Injecte `addrs.len()` paquets contigus.
    fn send(&self, packets: &[u8], addrs: &[Address]) -> io::Result<()>;
}

impl PacketSink for Handle {
    fn send(&self, packets: &[u8], addrs: &[Address]) -> io::Result<()> {
        self.send_batch(packets, addrs)
    }
}

pub struct Shared {
    pub gateway: Ipv4Addr,
    pub tcp_port: u16,
    pub subnet: Subnet,
    /// Index de l'interface du point d'accès ; 0 = inconnu.
    if_index: AtomicU32,
    pub nat: TcpNat,
    pub udp: UdpTable,
    pub stats: Stats,
    pub active_tcp: AtomicUsize,
    pub sink: Arc<dyn PacketSink>,
    pub rt: tokio::runtime::Handle,
    /// Seaux à jetons des appareils limités.
    pub limiter: RateLimiter,
    /// Requêtes DNS en cours de relais vers le résolveur imposé.
    pub dns_inflight: AtomicUsize,
    ident: AtomicU16,
    epoch: Instant,
    stop: watch::Sender<bool>,
    /// Politique courante : le verrou n'est tenu que le temps de cloner ou d'échanger l'Arc.
    policy: RwLock<Arc<Policy>>,
    /// Signalé à chaque changement de politique.
    policy_changed: watch::Sender<()>,
}

impl Shared {
    pub fn new(
        gateway: Ipv4Addr,
        tcp_port: u16,
        subnet: Subnet,
        sink: Arc<dyn PacketSink>,
        rt: tokio::runtime::Handle,
    ) -> Self {
        Self {
            gateway,
            tcp_port,
            subnet,
            if_index: AtomicU32::new(0),
            nat: TcpNat::new(),
            udp: UdpTable::default(),
            stats: Stats::default(),
            active_tcp: AtomicUsize::new(0),
            sink,
            rt,
            limiter: RateLimiter::default(),
            dns_inflight: AtomicUsize::new(0),
            ident: AtomicU16::new(1),
            epoch: Instant::now(),
            stop: watch::channel(false).0,
            policy: RwLock::new(Arc::new(Policy::default())),
            policy_changed: watch::channel(()).0,
        }
    }

    pub fn hotspot_if(&self) -> Option<u32> {
        match self.if_index.load(Relaxed) {
            0 => None,
            i => Some(i),
        }
    }

    pub fn set_hotspot_if(&self, idx: Option<u32>) {
        self.if_index.store(idx.unwrap_or(0), Relaxed);
    }

    /// Identifiant IPv4 incrémental des paquets fabriqués.
    pub fn next_ident(&self) -> u16 {
        self.ident.fetch_add(1, Relaxed)
    }

    /// Millisecondes écoulées depuis la création (horloge monotone des sessions UDP).
    pub fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    pub fn stop_signal(&self) -> watch::Receiver<bool> {
        self.stop.subscribe()
    }

    pub fn signal_stop(&self) {
        self.stop.send_replace(true);
    }

    /// Politique courante (lecture sans attente : le verrou n'est jamais tenu longtemps).
    pub fn policy(&self) -> Arc<Policy> {
        Arc::clone(&self.policy.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Remplace la politique, oublie les seaux des appareils qui ne sont plus limités et
    /// prévient les connexions en cours.
    pub fn set_policy(&self, policy: Policy) {
        let new = Arc::new(policy);
        let old = std::mem::replace(
            &mut *self.policy.write().unwrap_or_else(PoisonError::into_inner),
            Arc::clone(&new),
        );
        // L'ancienne politique est libérée hors du verrou.
        drop(old);
        self.limiter.retain(&new.limits);
        self.policy_changed.send_replace(());
    }

    /// Récepteur notifié à chaque changement de politique.
    pub fn policy_watch(&self) -> watch::Receiver<()> {
        self.policy_changed.subscribe()
    }

    /// Lissage : attente avant d'envoyer `n` octets de l'appareil `ip` (zéro sans limite).
    pub fn pace(
        &self,
        policy: &Policy,
        ip: Ipv4Addr,
        dir: Direction,
        n: usize,
        now: Instant,
    ) -> Duration {
        match policy.limit(ip) {
            Some(rate) => self.limiter.reserve(ip, dir, rate, n as u64, now),
            None => Duration::ZERO,
        }
    }

    /// Police : `n` octets de l'appareil `ip` peuvent-ils passer (toujours vrai sans limite) ?
    pub fn admit(
        &self,
        policy: &Policy,
        ip: Ipv4Addr,
        dir: Direction,
        n: usize,
        now: Instant,
    ) -> bool {
        match policy.limit(ip) {
            Some(rate) => self.limiter.try_take(ip, dir, rate, n as u64, now),
            None => true,
        }
    }
}

#[cfg(test)]
pub(crate) mod test_util {
    use super::*;
    use std::sync::Mutex;

    /// Puits de test qui enregistre les lots injectés.
    #[derive(Default)]
    pub struct MockSink {
        pub sent: Mutex<Vec<(Vec<u8>, Vec<Address>)>>,
    }

    impl PacketSink for MockSink {
        fn send(&self, packets: &[u8], addrs: &[Address]) -> io::Result<()> {
            self.sent
                .lock()
                .expect("mutex")
                .push((packets.to_vec(), addrs.to_vec()));
            Ok(())
        }
    }

    pub fn shared_with(
        gateway: Ipv4Addr,
        prefix: u8,
        tcp_port: u16,
    ) -> (Arc<Shared>, Arc<MockSink>) {
        let sink = Arc::new(MockSink::default());
        let subnet = Subnet::new(gateway, prefix).expect("sous-réseau");
        let shared = Shared::new(
            gateway,
            tcp_port,
            subnet,
            sink.clone(),
            tokio::runtime::Handle::current(),
        );
        (Arc::new(shared), sink)
    }
}
