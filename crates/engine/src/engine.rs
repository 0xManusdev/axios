//! Orchestration : handles WinDivert, threads de réception, runtime tokio.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use tokio::net::TcpListener;

use crate::error::EngineError;
use crate::ffi::{self, Address, Handle, WinDivert};
use crate::packet::{self, Proto};
use crate::policy::Policy;
use crate::shared::Shared;
use crate::stats::{EngineStats, Stats};
use crate::subnet::{self, Subnet};
use crate::{dns, dns_proxy, tcp_proxy, udp};

/// Taille du tampon de réception par lot (un lot peut regrouper jusqu'à 255 paquets).
const RECV_BUF_LEN: usize = 256 * 1024;
/// Paquets maximum par lot de réception.
const RECV_BATCH: usize = 64;
/// Échecs de réception consécutifs au-delà desquels un thread abandonne.
const MAX_CONSECUTIVE_RECV_ERRORS: u32 = 50;

/// Configuration du moteur.
#[derive(Clone, Debug)]
pub struct EngineConfig {
    /// IP du PC côté point d'accès (ICS), ex. 192.168.137.1.
    pub gateway: Ipv4Addr,
    /// Longueur du préfixe du réseau du point d'accès (24).
    pub prefix_len: u8,
    /// Port du proxy TCP transparent local, ex. 8229.
    pub tcp_port: u16,
    /// Chemin de `WinDivert.dll` (`WinDivert64.sys` dans le même dossier).
    pub windivert_dll: std::path::PathBuf,
}

/// Moteur NAT en espace utilisateur.
pub struct Engine {
    shared: Arc<Shared>,
    stopping: Arc<AtomicBool>,
    handles: Vec<Arc<Handle>>,
    threads: Vec<JoinHandle<()>>,
    runtime: Option<tokio::runtime::Runtime>,
}

impl Engine {
    /// Ouvre les handles WinDivert, lance les threads et le runtime. N'échoue pas si le point
    /// d'accès est éteint : le moteur reste au repos tant qu'aucun paquet ne passe.
    pub fn start(cfg: EngineConfig) -> Result<Engine, EngineError> {
        let subnet = Subnet::new(cfg.gateway, cfg.prefix_len)?;
        if cfg.tcp_port == 0 {
            return Err(EngineError::Config(
                "le port du proxy TCP doit être non nul".into(),
            ));
        }
        let lib = WinDivert::load(&cfg.windivert_dll)?;

        // Liaison avec un socket standard, avant le runtime : `block_on` serait interdit si
        // l'appelant est lui-même dans un runtime tokio.
        let std_listener =
            std::net::TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, cfg.tcp_port))
                .and_then(|l| l.set_nonblocking(true).map(|()| l))
                .map_err(EngineError::Bind)?;

        let h_fwd =
            Arc::new(lib.open(&subnet.forward_filter(), ffi::LAYER_NETWORK_FORWARD, 0, 0)?);
        let h_out = Arc::new(lib.open(
            &subnet::out_filter(cfg.gateway, cfg.tcp_port),
            ffi::LAYER_NETWORK,
            0,
            0,
        )?);
        let h_dns =
            Arc::new(lib.open(&subnet.dns_filter(cfg.gateway), ffi::LAYER_NETWORK, 0, 0)?);
        let h_inj = Arc::new(lib.open("false", ffi::LAYER_NETWORK, 0, ffi::FLAG_SEND_ONLY)?);

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .thread_name("pw-engine-rt")
            .enable_all()
            .build()
            .map_err(EngineError::Runtime)?;
        let listener = {
            let _guard = runtime.enter();
            TcpListener::from_std(std_listener)
        };
        let listener = match listener {
            Ok(l) => l,
            Err(e) => {
                // Lâcher un runtime dans un contexte asynchrone provoquerait une panique.
                runtime.shutdown_background();
                return Err(EngineError::Bind(e));
            }
        };

        let shared = Arc::new(Shared::new(
            cfg.gateway,
            cfg.tcp_port,
            subnet,
            h_inj.clone(),
            runtime.handle().clone(),
        ));
        runtime.spawn(tcp_proxy::serve(listener, Arc::clone(&shared)));
        runtime.spawn(tcp_proxy::maintenance(Arc::clone(&shared)));

        // À partir d'ici, `Drop` sait tout arrêter proprement en cas d'échec partiel.
        let mut engine = Engine {
            shared: Arc::clone(&shared),
            stopping: Arc::new(AtomicBool::new(false)),
            handles: vec![h_fwd.clone(), h_out.clone(), h_dns.clone(), h_inj],
            threads: Vec::new(),
            runtime: Some(runtime),
        };

        let stopping = Arc::clone(&engine.stopping);
        let sh = Arc::clone(&shared);
        let st = Arc::clone(&stopping);
        engine.spawn_thread("pw-forward", move || forward_loop(&sh, &h_fwd, &st))?;
        let sh = Arc::clone(&shared);
        let st = Arc::clone(&stopping);
        engine.spawn_thread("pw-reply", move || reply_loop(&sh, &h_out, &st))?;
        let sh = Arc::clone(&shared);
        engine.spawn_thread("pw-dns", move || dns_loop(&sh, &h_dns, &stopping))?;

        log::info!(
            "moteur démarré (passerelle {}, proxy TCP :{})",
            cfg.gateway,
            cfg.tcp_port
        );
        Ok(engine)
    }

    fn spawn_thread(
        &mut self,
        name: &str,
        f: impl FnOnce() + Send + 'static,
    ) -> Result<(), EngineError> {
        let handle = std::thread::Builder::new()
            .name(name.to_owned())
            .spawn(f)
            .map_err(EngineError::Runtime)?;
        self.threads.push(handle);
        Ok(())
    }

    /// Index de l'interface du point d'accès (`None` quand il s'arrête). Tant que `None`,
    /// les paquets interceptés sont ignorés. `Some(0)` est traité comme `None`.
    pub fn set_hotspot_interface(&self, if_index: Option<u32>) {
        log::info!("interface du point d'accès : {if_index:?}");
        self.shared.set_hotspot_if(if_index);
    }

    /// Remplace la politique (non bloquant, effet immédiat sur les paquets suivants).
    /// Les connexions TCP en cours d'un appareil qui devient bloqué sont fermées.
    pub fn set_policy(&self, policy: Policy) {
        log::info!(
            "politique : {} bloqué(s), {} limité(s), isolation {}, résolveur {:?}, liste de blocage {}",
            policy.blocked.len(),
            policy.limits.len(),
            policy.isolate,
            policy.dns.upstream,
            policy.dns.blocklist.as_ref().map_or(0, |b| b.len()),
        );
        self.shared.set_policy(policy);
    }

    /// Instantané des compteurs (non bloquant).
    pub fn stats(&self) -> EngineStats {
        self.shared
            .stats
            .snapshot(self.shared.active_tcp.load(Relaxed), self.shared.udp.len())
    }

    /// Arrêt propre : `WinDivertShutdown`, fin des threads, fermeture des sockets.
    pub fn shutdown(mut self) {
        self.stop();
    }

    fn stop(&mut self) {
        if self.stopping.swap(true, Relaxed) {
            return;
        }
        log::info!("arrêt du moteur");
        self.shared.signal_stop();
        for h in &self.handles {
            h.shutdown();
        }
        for t in self.threads.drain(..) {
            if t.join().is_err() {
                log::error!("un thread du moteur a paniqué");
            }
        }
        if let Some(rt) = self.runtime.take() {
            // Dans un contexte asynchrone, l'arrêt bloquant est interdit par tokio.
            if tokio::runtime::Handle::try_current().is_ok() {
                rt.shutdown_background();
            } else {
                rt.shutdown_timeout(Duration::from_secs(2));
            }
        }
        self.handles.clear();
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Réception d'un lot ; `None` quand le thread doit s'arrêter.
fn recv_or_stop(
    handle: &Handle,
    stopping: &AtomicBool,
    buf: &mut [u8],
    addrs: &mut [Address],
    failures: &mut u32,
    name: &str,
) -> Option<ffi::RecvBatch> {
    match handle.recv_batch(buf, addrs) {
        Ok(batch) => {
            *failures = 0;
            Some(batch)
        }
        Err(e) => {
            if stopping.load(Relaxed) {
                return None;
            }
            *failures += 1;
            log::warn!("{name} : réception impossible : {e}");
            if *failures >= MAX_CONSECUTIVE_RECV_ERRORS {
                log::error!("{name} : trop d'échecs consécutifs, arrêt du thread");
                return None;
            }
            std::thread::sleep(Duration::from_millis(100));
            Some(ffi::RecvBatch { bytes: 0, count: 0 })
        }
    }
}

/// Itère sur les paquets d'un lot : `(index, octets)`.
fn batch_packets(buf: &[u8], batch: ffi::RecvBatch) -> impl Iterator<Item = (usize, &[u8])> {
    let mut off = 0;
    (0..batch.count).map_while(move |i| {
        let len = packet::packet_len(&buf[off..batch.bytes])?;
        let pkt = &buf[off..off + len];
        off += len;
        Some((i, pkt))
    })
}

/// Téléphone -> internet : TCP réinjecté vers le proxy local, UDP envoyé par socket.
fn forward_loop(shared: &Arc<Shared>, handle: &Handle, stopping: &AtomicBool) {
    let mut buf = vec![0u8; RECV_BUF_LEN];
    let mut addrs = vec![Address::default(); RECV_BATCH];
    let mut out: Vec<u8> = Vec::with_capacity(RECV_BUF_LEN);
    let mut out_addrs: Vec<Address> = Vec::with_capacity(RECV_BATCH);
    let mut failures = 0;
    let proxy = SocketAddrV4::new(shared.gateway, shared.tcp_port);

    while let Some(batch) = recv_or_stop(
        handle,
        stopping,
        &mut buf,
        &mut addrs,
        &mut failures,
        "pw-forward",
    ) {
        out.clear();
        out_addrs.clear();
        let if_idx = shared.hotspot_if();
        let now = Instant::now();
        // Une lecture de la politique par lot.
        let policy = shared.policy();

        for (_, pkt) in batch_packets(&buf, batch) {
            let Ok(info) = packet::parse(pkt) else {
                Stats::count(&shared.stats.dropped);
                continue;
            };
            let Some(if_idx) = if_idx else {
                Stats::count(&shared.stats.dropped);
                continue;
            };
            if !forward_allowed(&policy, &info) {
                Stats::count(&shared.stats.dropped);
                continue;
            }
            match info.proto {
                Proto::Tcp => {
                    Stats::count(&shared.stats.fwd_tcp);
                    if shared
                        .nat
                        .rewrite_to_proxy(pkt, &info, proxy, &mut out, now)
                    {
                        out_addrs.push(Address::network(if_idx, 0, false));
                    } else {
                        Stats::count(&shared.stats.dropped);
                    }
                }
                Proto::Udp => {
                    Stats::count(&shared.stats.fwd_udp);
                    let payload = info.udp_payload(pkt);
                    // Requête DNS vers un résolveur extérieur : liste de blocage.
                    if info.dst.port() == dns::PORT
                        && dns_proxy::answer_if_blocked(
                            shared, &policy, info.src, info.dst, payload, if_idx,
                        )
                    {
                        continue;
                    }
                    udp::forward_with(shared, &policy, info.src, info.dst, payload);
                }
            }
        }
        inject(shared, &out, &out_addrs);
    }
    log::debug!("pw-forward terminé");
}

/// Un paquet relayé passe-t-il la politique (appareil non bloqué, destination permise) ?
fn forward_allowed(policy: &Policy, info: &packet::PacketInfo) -> bool {
    !policy.is_blocked(*info.src.ip()) && !policy.drops_destination(*info.dst.ip())
}

/// Requêtes DNS des appareils vers le PC : abandon, NXDOMAIN, relais ou réinjection.
fn dns_loop(shared: &Arc<Shared>, handle: &Handle, stopping: &AtomicBool) {
    let mut buf = vec![0u8; RECV_BUF_LEN];
    let mut addrs = vec![Address::default(); RECV_BATCH];
    let mut pass: Vec<u8> = Vec::with_capacity(RECV_BUF_LEN);
    let mut pass_addrs: Vec<Address> = Vec::with_capacity(RECV_BATCH);
    let mut failures = 0;

    while let Some(batch) = recv_or_stop(
        handle,
        stopping,
        &mut buf,
        &mut addrs,
        &mut failures,
        "pw-dns",
    ) {
        pass.clear();
        pass_addrs.clear();
        let policy = shared.policy();
        for (i, pkt) in batch_packets(&buf, batch) {
            if dns_proxy::on_gateway_packet(shared, &policy, pkt, &addrs[i]) {
                pass.extend_from_slice(pkt);
                // Même adresse WinDivert : Windows traite la requête normalement.
                pass_addrs.push(addrs[i]);
            }
        }
        if !pass_addrs.is_empty() {
            if let Err(e) = handle.send_batch(&pass, &pass_addrs) {
                log::debug!("pw-dns : réinjection impossible : {e}");
                Stats::count(&shared.stats.errors);
            }
        }
    }
    log::debug!("pw-dns terminé");
}

/// Proxy local -> téléphone : remet l'adresse d'origine comme source.
fn reply_loop(shared: &Arc<Shared>, handle: &Handle, stopping: &AtomicBool) {
    let mut buf = vec![0u8; RECV_BUF_LEN];
    let mut addrs = vec![Address::default(); RECV_BATCH];
    let mut out: Vec<u8> = Vec::with_capacity(RECV_BUF_LEN);
    let mut out_addrs: Vec<Address> = Vec::with_capacity(RECV_BATCH);
    let mut failures = 0;

    while let Some(batch) = recv_or_stop(
        handle,
        stopping,
        &mut buf,
        &mut addrs,
        &mut failures,
        "pw-reply",
    ) {
        out.clear();
        out_addrs.clear();
        for (i, pkt) in batch_packets(&buf, batch) {
            let rewritten = packet::parse(pkt)
                .ok()
                .is_some_and(|info| shared.nat.rewrite_from_proxy(pkt, &info, &mut out));
            if rewritten {
                // Même adresse (sortant, interface) que celle du paquet capturé.
                out_addrs.push(addrs[i]);
                Stats::count(&shared.stats.reflected_out);
            } else {
                Stats::count(&shared.stats.dropped);
            }
        }
        // Réinjection par le handle de capture lui-même, comme le prototype.
        if !out_addrs.is_empty() {
            if let Err(e) = handle.send_batch(&out, &out_addrs) {
                log::debug!("pw-reply : injection impossible : {e}");
                Stats::count(&shared.stats.errors);
            }
        }
    }
    log::debug!("pw-reply terminé");
}

fn inject(shared: &Shared, packets: &[u8], addrs: &[Address]) {
    if addrs.is_empty() {
        return;
    }
    if let Err(e) = shared.sink.send(packets, addrs) {
        log::debug!("injection impossible : {e}");
        Stats::count(&shared.stats.errors);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{
        tcp_flags,
        tests::{sa, tcp_packet},
    };

    #[test]
    fn batch_packets_splits_contiguous_packets() {
        let a = tcp_packet(sa(1, 1, 1, 1, 1), sa(2, 2, 2, 2, 2), tcp_flags::ACK, b"abc");
        let b = tcp_packet(sa(3, 3, 3, 3, 3), sa(4, 4, 4, 4, 4), tcp_flags::ACK, b"");
        let mut buf = [a.clone(), b.clone()].concat();
        buf.extend_from_slice(&[0xAA; 100]); // reste du tampon, non initialisé par WinDivert
        let batch = ffi::RecvBatch {
            bytes: a.len() + b.len(),
            count: 2,
        };
        let got: Vec<_> = batch_packets(&buf, batch).collect();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], (0, &a[..]));
        assert_eq!(got[1], (1, &b[..]));
    }

    #[test]
    fn batch_packets_stops_on_corrupt_data() {
        let a = tcp_packet(sa(1, 1, 1, 1, 1), sa(2, 2, 2, 2, 2), tcp_flags::ACK, b"abc");
        let mut buf = a.clone();
        buf.extend_from_slice(&[0xFF; 30]);
        let batch = ffi::RecvBatch {
            bytes: buf.len(),
            count: 2,
        };
        assert_eq!(batch_packets(&buf, batch).count(), 1);
    }

    #[test]
    fn forward_respects_blocking_and_isolation() {
        let phone = sa(192, 168, 137, 50, 40000);
        let info = |dst| packet::parse(&tcp_packet(phone, dst, tcp_flags::SYN, &[])).unwrap();
        let public = info(sa(93, 184, 216, 34, 443));
        let lan = info(sa(192, 168, 1, 1, 80));

        let mut policy = Policy::default();
        assert!(forward_allowed(&policy, &public));
        assert!(forward_allowed(&policy, &lan), "isolation désactivée");

        policy.isolate = true;
        assert!(forward_allowed(&policy, &public));
        assert!(!forward_allowed(&policy, &lan));
        assert!(!forward_allowed(&policy, &info(sa(100, 64, 0, 1, 53))));

        policy.blocked.insert(*phone.ip());
        assert!(!forward_allowed(&policy, &public));
    }

    #[test]
    fn start_reports_missing_dll_and_bad_config() {
        let cfg = EngineConfig {
            gateway: Ipv4Addr::new(192, 168, 137, 1),
            prefix_len: 24,
            tcp_port: 8229,
            windivert_dll: "C:\\inexistant\\WinDivert.dll".into(),
        };
        match Engine::start(cfg.clone()) {
            Err(EngineError::DllLoad { .. }) => {}
            other => panic!("DllLoad attendu, obtenu {:?}", other.err()),
        }
        let bad = EngineConfig {
            prefix_len: 40,
            ..cfg
        };
        assert!(matches!(Engine::start(bad), Err(EngineError::Config(_))));
    }
}
