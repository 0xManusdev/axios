//! Interception DNS selon la politique :
//! - requêtes des appareils vers le DNS de Windows (`gateway:53`, handle dédié) : abandon
//!   (appareil bloqué), réponse `NXDOMAIN` (domaine bloqué), relais vers le résolveur imposé,
//!   ou réinjection telle quelle ;
//! - requêtes relayées vers un résolveur extérieur (port 53, via `udp::forward`) : seule la
//!   liste de blocage s'applique.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::dns::{self, Query};
use crate::ffi::Address;
use crate::packet::{self, Proto};
use crate::policy::Policy;
use crate::shared::Shared;
use crate::stats::Stats;
use crate::udp;

/// Délai de réponse du résolveur imposé.
pub const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);
/// Requêtes relayées simultanément au-delà desquelles les nouvelles sont abandonnées.
const MAX_INFLIGHT: usize = 256;
/// Taille maximale d'une réponse DNS sur UDP.
const RESPONSE_BUF_LEN: usize = 65_535;
/// En-têtes IPv4 + UDP d'un datagramme fabriqué.
const DATAGRAM_OVERHEAD: usize = packet::IPV4_HEADER_LEN + packet::UDP_HEADER_LEN;

/// Sort d'une requête reçue sur `gateway:53`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Abandonnée sans réponse (appareil bloqué).
    Drop,
    /// Réinjectée telle quelle : Windows répond normalement.
    Pass,
    /// Réponse `NXDOMAIN` fabriquée (domaine bloqué).
    NxDomain,
    /// Relayée vers ce résolveur.
    Forward(Ipv4Addr),
}

/// Résolveur imposé utilisable (unicast).
fn usable_upstream(ip: Ipv4Addr) -> bool {
    !(ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast())
}

/// Décision pour une requête de l'appareil `src` vers `gateway:53` ; `query` vaut `None` si
/// le message n'a pas pu être analysé (il n'est alors jamais bloqué par nom).
pub fn decide(policy: &Policy, src: Ipv4Addr, query: Option<&Query>) -> Action {
    if policy.is_blocked(src) {
        return Action::Drop;
    }
    if query.is_some_and(|q| policy.blocks_domain(&q.name)) {
        return Action::NxDomain;
    }
    match policy.dns.upstream {
        Some(up) if usable_upstream(up) => Action::Forward(up),
        _ => Action::Pass,
    }
}

/// Source IPv4 brute d'un paquet, même non analysable par [`packet::parse`].
fn raw_source(pkt: &[u8]) -> Option<Ipv4Addr> {
    let b = pkt.get(12..16)?;
    (pkt.first()? >> 4 == 4).then(|| Ipv4Addr::new(b[0], b[1], b[2], b[3]))
}

/// Traite un paquet capturé vers `gateway:53` (adresse WinDivert `addr`). Renvoie `true` s'il
/// doit être réinjecté tel quel par l'appelant ; sinon il a été abandonné, servi ou relayé.
pub fn on_gateway_packet(
    shared: &Arc<Shared>,
    policy: &Policy,
    pkt: &[u8],
    addr: &Address,
) -> bool {
    let info = match packet::parse(pkt) {
        Ok(info) if info.proto == Proto::Udp => info,
        // Fragment ou paquet inattendu : laissé à Windows, sauf appareil bloqué.
        _ => {
            if raw_source(pkt).is_some_and(|ip| policy.is_blocked(ip)) {
                Stats::count(&shared.stats.dropped);
                return false;
            }
            return true;
        }
    };
    let payload = info.udp_payload(pkt);
    let query = dns::parse_query(payload).ok();
    // Interface du point d'accès, à défaut celle par laquelle la requête est arrivée.
    let if_idx = shared.hotspot_if().unwrap_or_else(|| addr.if_idx());
    match decide(policy, *info.src.ip(), query.as_ref()) {
        Action::Drop => {
            Stats::count(&shared.stats.dropped);
            false
        }
        Action::Pass => true,
        Action::NxDomain => {
            if let Some(q) = &query {
                answer_nxdomain(shared, payload, q, info.dst, info.src, if_idx);
            }
            false
        }
        Action::Forward(upstream) => {
            spawn_forward(shared, info.src, info.dst, upstream, payload, if_idx);
            false
        }
    }
}

/// Requête DNS relayée (appareil qui interroge directement `server`, port 53) : si le nom est
/// bloqué, répond `NXDOMAIN` au nom de `server` et renvoie `true` (la requête n'est pas
/// transmise). `false` dans tous les autres cas.
pub fn answer_if_blocked(
    shared: &Shared,
    policy: &Policy,
    client: SocketAddrV4,
    server: SocketAddrV4,
    payload: &[u8],
    if_idx: u32,
) -> bool {
    if server.port() != dns::PORT || policy.dns.blocklist.is_none() {
        return false;
    }
    let Ok(query) = dns::parse_query(payload) else {
        return false;
    };
    if !policy.blocks_domain(&query.name) {
        return false;
    }
    answer_nxdomain(shared, payload, &query, server, client, if_idx);
    true
}

/// Fabrique et injecte la réponse `NXDOMAIN` `server -> client`.
fn answer_nxdomain(
    shared: &Shared,
    msg: &[u8],
    query: &Query,
    server: SocketAddrV4,
    client: SocketAddrV4,
    if_idx: u32,
) {
    let Some(response) = dns::nxdomain(msg, query) else {
        Stats::count(&shared.stats.dropped);
        return;
    };
    Stats::count(&shared.stats.ads_blocked);
    log::debug!("DNS bloqué pour {} : {}", client.ip(), query.name);
    let mut out = Vec::with_capacity(DATAGRAM_OVERHEAD + response.len());
    let mut addrs = Vec::with_capacity(1);
    udp::inject_datagram(
        shared, server, client, &response, if_idx, &mut out, &mut addrs,
    );
}

/// Place réservée parmi les requêtes relayées en cours, rendue à la destruction.
struct Inflight(Arc<Shared>);

impl Inflight {
    fn acquire(shared: &Arc<Shared>) -> Option<Self> {
        if shared.dns_inflight.fetch_add(1, Relaxed) >= MAX_INFLIGHT {
            shared.dns_inflight.fetch_sub(1, Relaxed);
            return None;
        }
        Some(Self(Arc::clone(shared)))
    }
}

impl Drop for Inflight {
    fn drop(&mut self) {
        self.0.dns_inflight.fetch_sub(1, Relaxed);
    }
}

/// Relaie la requête `client -> server` vers `upstream:53` dans une tâche tokio ; la réponse
/// revient de `server` vers `client` sur l'interface `if_idx`.
fn spawn_forward(
    shared: &Arc<Shared>,
    client: SocketAddrV4,
    server: SocketAddrV4,
    upstream: Ipv4Addr,
    query: &[u8],
    if_idx: u32,
) {
    let Some(slot) = Inflight::acquire(shared) else {
        log::debug!("trop de requêtes DNS en cours : requête de {client} abandonnée");
        Stats::count(&shared.stats.dropped);
        return;
    };
    let query = query.to_vec();
    let target = SocketAddrV4::new(upstream, dns::PORT);
    shared.rt.spawn(async move {
        relay_query(&slot.0, client, server, target, &query, if_idx).await;
        drop(slot);
    });
}

/// Interroge `target` (délai [`UPSTREAM_TIMEOUT`]) puis injecte la réponse `server -> client`.
async fn relay_query(
    shared: &Shared,
    client: SocketAddrV4,
    server: SocketAddrV4,
    target: SocketAddrV4,
    query: &[u8],
    if_idx: u32,
) {
    let response = match timeout(UPSTREAM_TIMEOUT, exchange(query, target)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            log::debug!("résolveur {target} : {e}");
            Stats::count(&shared.stats.errors);
            return;
        }
        Err(_) => {
            log::debug!("résolveur {target} : délai dépassé");
            Stats::count(&shared.stats.dropped);
            return;
        }
    };
    let mut out = Vec::with_capacity(DATAGRAM_OVERHEAD + response.len());
    let mut addrs = Vec::with_capacity(1);
    udp::inject_datagram(
        shared, server, client, &response, if_idx, &mut out, &mut addrs,
    );
}

/// Envoie `query` à `target` et attend la réponse portant le même identifiant (les autres
/// datagrammes sont ignorés).
async fn exchange(query: &[u8], target: SocketAddrV4) -> io::Result<Vec<u8>> {
    let id = dns::message_id(query)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "requête DNS tronquée"))?;
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    socket.send_to(query, target).await?;
    let mut buf = vec![0u8; RESPONSE_BUF_LEN];
    loop {
        let (n, from) = socket.recv_from(&mut buf).await?;
        if from == SocketAddr::V4(target) && dns::is_response_to(&buf[..n], id) {
            buf.truncate(n);
            return Ok(buf);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::tests::query as dns_query;
    use crate::packet::tests::sa;
    use crate::packet::{checksums_valid, parse, UdpDatagram, DEFAULT_MTU};
    use crate::policy::Blocklist;
    use crate::shared::test_util::{shared_with, MockSink};

    const GW: Ipv4Addr = Ipv4Addr::new(192, 168, 137, 1);

    fn blocklist(text: &str) -> Option<Arc<Blocklist>> {
        Some(Arc::new(Blocklist::parse(text)))
    }

    /// Paquet IPv4/UDP `src -> dst` portant `payload`.
    fn udp_packet(src: SocketAddrV4, dst: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let d = UdpDatagram {
            src,
            dst,
            ident: 1,
            ttl: 128,
            payload,
        };
        packet::append_udp_packets(&mut out, &d, DEFAULT_MTU).unwrap();
        out
    }

    /// Unique paquet injecté : (source, destination, charge utile, adresse).
    fn single_injected(sink: &MockSink) -> (SocketAddrV4, SocketAddrV4, Vec<u8>, Address) {
        let sent = sink.sent.lock().unwrap();
        assert_eq!(sent.len(), 1, "un seul lot attendu");
        let (bytes, addrs) = &sent[0];
        assert_eq!(addrs.len(), 1);
        let info = parse(bytes).unwrap();
        assert!(checksums_valid(bytes, &info));
        (
            info.src,
            info.dst,
            info.udp_payload(bytes).to_vec(),
            addrs[0],
        )
    }

    #[test]
    fn decide_applies_policy_in_order() {
        let phone = Ipv4Addr::new(192, 168, 137, 50);
        let ads = dns::parse_query(&dns_query(1, "ads.example.com")).unwrap();
        let ok = dns::parse_query(&dns_query(2, "example.org")).unwrap();

        let mut p = Policy::default();
        assert_eq!(decide(&p, phone, Some(&ads)), Action::Pass);
        assert_eq!(decide(&p, phone, None), Action::Pass);

        p.dns.blocklist = blocklist("example.com");
        assert_eq!(decide(&p, phone, Some(&ads)), Action::NxDomain);
        assert_eq!(decide(&p, phone, Some(&ok)), Action::Pass);
        assert_eq!(
            decide(&p, phone, None),
            Action::Pass,
            "illisible : jamais bloqué par nom"
        );

        p.dns.upstream = Some(Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(
            decide(&p, phone, Some(&ads)),
            Action::NxDomain,
            "liste avant relais"
        );
        assert_eq!(
            decide(&p, phone, Some(&ok)),
            Action::Forward(Ipv4Addr::new(1, 1, 1, 1))
        );
        assert_eq!(
            decide(&p, phone, None),
            Action::Forward(Ipv4Addr::new(1, 1, 1, 1))
        );

        p.blocked.insert(phone);
        assert_eq!(
            decide(&p, phone, Some(&ok)),
            Action::Drop,
            "appareil bloqué d'abord"
        );

        for bad in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(224, 0, 0, 1),
        ] {
            let p = Policy {
                dns: crate::policy::DnsPolicy {
                    upstream: Some(bad),
                    blocklist: None,
                },
                ..Policy::default()
            };
            assert_eq!(decide(&p, phone, Some(&ok)), Action::Pass, "{bad}");
        }
    }

    #[test]
    fn raw_source_reads_ipv4_only() {
        let p = udp_packet(sa(192, 168, 137, 9, 1), sa(192, 168, 137, 1, 53), b"x");
        assert_eq!(raw_source(&p), Some(Ipv4Addr::new(192, 168, 137, 9)));
        assert_eq!(raw_source(&p[..15]), None);
        let mut v6 = p.clone();
        v6[0] = 0x60;
        assert_eq!(raw_source(&v6), None);
        assert_eq!(raw_source(&[]), None);
    }

    #[tokio::test]
    async fn gateway_queries_follow_policy() {
        let (shared, sink) = shared_with(GW, 24, 8229);
        shared.set_hotspot_if(Some(12));
        let phone = sa(192, 168, 137, 50, 5353);
        let server = SocketAddrV4::new(GW, 53);
        let captured = Address::network(12, 0, false);
        let msg = dns_query(0x1234, "Ads.Example.com");
        let pkt = udp_packet(phone, server, &msg);

        // Politique par défaut : réinjection telle quelle.
        let mut policy = Policy::default();
        assert!(on_gateway_packet(&shared, &policy, &pkt, &captured));
        assert!(sink.sent.lock().unwrap().is_empty());

        // Nom bloqué : NXDOMAIN de gateway:53 vers l'appareil, injecté en sortie.
        policy.dns.blocklist = blocklist("0.0.0.0 example.com");
        assert!(!on_gateway_packet(&shared, &policy, &pkt, &captured));
        let (src, dst, payload, addr) = single_injected(&sink);
        assert_eq!((src, dst), (server, phone));
        assert!(addr.outbound());
        assert_eq!(addr.if_idx(), 12);
        assert!(dns::is_response_to(&payload, 0x1234));
        assert_eq!(payload[3] & 0x0F, dns::RCODE_NXDOMAIN as u8);
        assert_eq!(shared.stats.snapshot(0, 0).ads_blocked, 1);

        // Nom autorisé : réinjecté.
        let other = udp_packet(phone, server, &dns_query(7, "example.org"));
        assert!(on_gateway_packet(&shared, &policy, &other, &captured));

        // Appareil bloqué : abandon, même pour un paquet illisible.
        policy.blocked.insert(*phone.ip());
        assert!(!on_gateway_packet(&shared, &policy, &other, &captured));
        let mut frag = other.clone();
        frag[6] = 0x20; // MF : fragment, non analysable
        assert!(!on_gateway_packet(&shared, &policy, &frag, &captured));
        assert_eq!(shared.stats.snapshot(0, 0).packets.dropped, 2);

        // Paquet illisible d'un appareil autorisé : laissé à Windows.
        policy.blocked.clear();
        assert!(on_gateway_packet(&shared, &policy, &frag, &captured));
        assert!(on_gateway_packet(&shared, &policy, &[0xFF; 7], &captured));
        assert_eq!(sink.sent.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn nxdomain_uses_capture_interface_when_hotspot_unknown() {
        let (shared, sink) = shared_with(GW, 24, 8229);
        let mut policy = Policy::default();
        policy.dns.blocklist = blocklist("tracker.net");
        let pkt = udp_packet(
            sa(192, 168, 137, 60, 999),
            SocketAddrV4::new(GW, 53),
            &dns_query(5, "x.tracker.net"),
        );
        assert!(!on_gateway_packet(
            &shared,
            &policy,
            &pkt,
            &Address::network(33, 0, false)
        ));
        assert_eq!(single_injected(&sink).3.if_idx(), 33);
    }

    #[tokio::test]
    async fn relayed_queries_are_answered_on_behalf_of_the_resolver() {
        let (shared, sink) = shared_with(GW, 24, 8229);
        let phone = sa(192, 168, 137, 50, 40000);
        let google = sa(8, 8, 8, 8, 53);
        let msg = dns_query(0xBEEF, "ads.example.com");
        let mut policy = Policy::default();
        assert!(
            !answer_if_blocked(&shared, &policy, phone, google, &msg, 4),
            "pas de liste"
        );

        policy.dns.blocklist = blocklist("example.com");
        assert!(!answer_if_blocked(
            &shared,
            &policy,
            phone,
            sa(8, 8, 8, 8, 5353),
            &msg,
            4
        ));
        assert!(!answer_if_blocked(
            &shared,
            &policy,
            phone,
            google,
            b"\x00\x01",
            4
        ));
        let fine = dns_query(1, "example.org");
        assert!(!answer_if_blocked(
            &shared, &policy, phone, google, &fine, 4
        ));
        assert!(sink.sent.lock().unwrap().is_empty());

        assert!(answer_if_blocked(&shared, &policy, phone, google, &msg, 4));
        let (src, dst, payload, addr) = single_injected(&sink);
        assert_eq!((src, dst), (google, phone));
        assert_eq!(addr.if_idx(), 4);
        assert!(dns::is_response_to(&payload, 0xBEEF));
        assert_eq!(shared.stats.snapshot(0, 0).ads_blocked, 1);
    }

    /// Faux résolveur local : envoie d'abord une réponse d'identifiant erroné, puis la bonne
    /// (requête renvoyée avec QR posé et le marqueur `extra`).
    async fn fake_resolver(extra: &'static [u8]) -> SocketAddrV4 {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let SocketAddr::V4(addr) = sock.local_addr().unwrap() else {
            unreachable!("IPv4 attendu");
        };
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1500];
            while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                let mut resp = buf[..n].to_vec();
                resp[2] |= 0x80;
                let mut wrong = resp.clone();
                wrong[0] ^= 0xFF;
                let _ = sock.send_to(&wrong, peer).await;
                resp.extend_from_slice(extra);
                let _ = sock.send_to(&resp, peer).await;
            }
        });
        addr
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn upstream_answer_is_returned_from_gateway() {
        let (shared, sink) = shared_with(GW, 24, 8229);
        let resolver = fake_resolver(b"ok").await;
        let phone = sa(192, 168, 137, 50, 5353);
        let server = SocketAddrV4::new(GW, 53);
        let msg = dns_query(0x0A0B, "example.org");
        relay_query(&shared, phone, server, resolver, &msg, 9).await;
        let (src, dst, payload, addr) = single_injected(&sink);
        assert_eq!((src, dst), (server, phone));
        assert_eq!(addr.if_idx(), 9);
        assert!(addr.outbound());
        assert!(
            dns::is_response_to(&payload, 0x0A0B),
            "mauvais identifiant ignoré"
        );
        assert!(payload.ends_with(b"ok"));
    }

    #[tokio::test]
    async fn exchange_rejects_truncated_query() {
        let err = exchange(&[0x01], sa(127, 0, 0, 1, 9)).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn inflight_slots_are_bounded_and_released() {
        let (shared, _sink) = shared_with(GW, 24, 8229);
        let slots: Vec<_> = (0..MAX_INFLIGHT)
            .map(|_| Inflight::acquire(&shared).expect("place libre"))
            .collect();
        assert!(Inflight::acquire(&shared).is_none());
        assert_eq!(shared.dns_inflight.load(Relaxed), MAX_INFLIGHT);
        drop(slots);
        assert_eq!(shared.dns_inflight.load(Relaxed), 0);
        assert!(Inflight::acquire(&shared).is_some());
    }
}
