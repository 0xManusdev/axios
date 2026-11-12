//! Sessions UDP : un socket local par `(IP, port)` du téléphone, indépendant de la destination
//! (compatible STUN / appels), expiré après [`IDLE_TIMEOUT`] d'inactivité.
//!
//! L'envoi se fait depuis le thread WinDivert (`send_to` non bloquant) ; chaque session a
//! une tâche tokio qui reçoit les réponses, fabrique les paquets IPv4/UDP (fragmentés si
//! besoin) et les injecte en sortie sur l'interface du point d'accès.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};

use crate::ffi::Address;
use crate::packet::{self, UdpDatagram, DEFAULT_MTU};
use crate::policy::Policy;
use crate::ratelimit::Direction;
use crate::shared::Shared;
use crate::stats::Stats;

/// Inactivité au bout de laquelle une session est fermée.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(180);
const REPLY_TTL: u8 = 64;
const RECV_BUF_LEN: usize = 65_536;

/// Temps restant avant expiration, ou `None` si la session est expirée.
pub fn idle_remaining(last_used_ms: u64, now_ms: u64, idle: Duration) -> Option<Duration> {
    let elapsed = Duration::from_millis(now_ms.saturating_sub(last_used_ms));
    idle.checked_sub(elapsed).filter(|d| !d.is_zero())
}

pub struct Session {
    /// Réception asynchrone (tâche de session).
    socket: UdpSocket,
    /// Même socket, pour l'envoi non bloquant depuis le thread WinDivert : `try_send_to` de
    /// tokio refuse d'écrire tant que la préparation n'a pas été signalée par le réacteur
    /// (le premier datagramme serait perdu).
    sender: std::net::UdpSocket,
    last_used_ms: AtomicU64,
}

impl Session {
    fn touch(&self, now_ms: u64) {
        self.last_used_ms.fetch_max(now_ms, Relaxed);
    }
}

#[derive(Default)]
pub struct UdpTable {
    sessions: DashMap<SocketAddrV4, Arc<Session>>,
}

impl UdpTable {
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

fn open_session(shared: &Arc<Shared>, client: SocketAddrV4) -> io::Result<Arc<Session>> {
    let std_socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    std_socket.set_nonblocking(true)?;
    let sender = std_socket.try_clone()?;
    let socket = {
        let _guard = shared.rt.enter();
        UdpSocket::from_std(std_socket)?
    };
    let session = Arc::new(Session {
        socket,
        sender,
        last_used_ms: AtomicU64::new(shared.now_ms()),
    });
    shared.rt.spawn(session_task(
        Arc::clone(shared),
        client,
        Arc::clone(&session),
    ));
    Ok(session)
}

/// Envoie `payload` du téléphone `client` vers `dst` via sa session (créée au besoin), selon
/// la politique courante.
pub fn forward(shared: &Arc<Shared>, client: SocketAddrV4, dst: SocketAddrV4, payload: &[u8]) {
    forward_with(shared, &shared.policy(), client, dst, payload);
}

/// Comme [`forward`], avec la politique déjà lue par l'appelant (une lecture par lot). Un
/// appareil bloqué ou sans jetons disponibles (limite de débit) voit son paquet abandonné.
pub fn forward_with(
    shared: &Arc<Shared>,
    policy: &Policy,
    client: SocketAddrV4,
    dst: SocketAddrV4,
    payload: &[u8],
) {
    let ip = *client.ip();
    if policy.is_blocked(ip)
        || !shared.admit(policy, ip, Direction::Up, payload.len(), Instant::now())
    {
        Stats::count(&shared.stats.dropped);
        return;
    }
    let session = match shared.udp.sessions.get(&client) {
        Some(s) => Arc::clone(&s),
        None => match open_session(shared, client) {
            Ok(s) => {
                shared.udp.sessions.insert(client, Arc::clone(&s));
                log::debug!("session UDP ouverte pour {client}");
                s
            }
            Err(e) => {
                log::warn!("socket UDP impossible pour {client} : {e}");
                Stats::count(&shared.stats.errors);
                return;
            }
        },
    };
    session.touch(shared.now_ms());
    match session.sender.send_to(payload, SocketAddr::V4(dst)) {
        Ok(_) => shared.stats.add_up(*client.ip(), payload.len() as u64),
        Err(e) => {
            log::debug!("envoi UDP {client} -> {dst} : {e}");
            Stats::count(&shared.stats.dropped);
        }
    }
}

async fn session_task(shared: Arc<Shared>, client: SocketAddrV4, session: Arc<Session>) {
    let mut stop = shared.stop_signal();
    let mut buf = vec![0u8; RECV_BUF_LEN];
    let mut out: Vec<u8> = Vec::with_capacity(2048);
    let mut addrs: Vec<Address> = Vec::with_capacity(4);

    loop {
        let last = session.last_used_ms.load(Relaxed);
        let Some(remaining) = idle_remaining(last, shared.now_ms(), IDLE_TIMEOUT) else {
            break;
        };
        let received = tokio::select! {
            r = timeout(remaining, session.socket.recv_from(&mut buf)) => r,
            _ = stop.changed() => break,
        };
        match received {
            Err(_) => continue, // délai écoulé : réévaluer l'inactivité
            Ok(Ok((n, SocketAddr::V4(from)))) => {
                let policy = shared.policy();
                if policy.is_blocked(*client.ip()) {
                    // Appareil bloqué : la session est fermée sans attendre l'inactivité.
                    Stats::count(&shared.stats.dropped);
                    break;
                }
                session.touch(shared.now_ms());
                reply(
                    &shared,
                    &policy,
                    client,
                    from,
                    &buf[..n],
                    &mut out,
                    &mut addrs,
                );
            }
            Ok(Ok(_)) => {}
            // Windows signale par ConnectionReset un ICMP « port inaccessible » reçu pour un
            // envoi précédent : sans gravité, la session continue.
            Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionReset => {}
            Ok(Err(e)) => {
                log::debug!("réception UDP {client} : {e}");
                Stats::count(&shared.stats.errors);
                sleep(Duration::from_millis(10)).await;
            }
        }
    }

    shared
        .udp
        .sessions
        .remove_if(&client, |_, s| Arc::ptr_eq(s, &session));
    log::debug!("session UDP fermée pour {client}");
}

/// Fabrique les paquets de la réponse `from -> client` et les injecte en sortie (abandonnée
/// si l'appareil n'a pas de jetons disponibles).
fn reply(
    shared: &Shared,
    policy: &Policy,
    client: SocketAddrV4,
    from: SocketAddrV4,
    payload: &[u8],
    out: &mut Vec<u8>,
    addrs: &mut Vec<Address>,
) {
    let Some(if_idx) = shared.hotspot_if() else {
        Stats::count(&shared.stats.dropped);
        return;
    };
    if !shared.admit(
        policy,
        *client.ip(),
        Direction::Down,
        payload.len(),
        Instant::now(),
    ) {
        Stats::count(&shared.stats.dropped);
        return;
    }
    if inject_datagram(shared, from, client, payload, if_idx, out, addrs) {
        Stats::count(&shared.stats.udp_back);
        shared.stats.add_down(*client.ip(), payload.len() as u64);
    }
}

/// Fabrique le datagramme `from -> to` (fragmenté si besoin) et l'injecte en sortie sur
/// l'interface `if_idx`. Les échecs sont comptés ; renvoie `true` si l'injection a réussi.
pub fn inject_datagram(
    shared: &Shared,
    from: SocketAddrV4,
    to: SocketAddrV4,
    payload: &[u8],
    if_idx: u32,
    out: &mut Vec<u8>,
    addrs: &mut Vec<Address>,
) -> bool {
    out.clear();
    let datagram = UdpDatagram {
        src: from,
        dst: to,
        ident: shared.next_ident(),
        ttl: REPLY_TTL,
        payload,
    };
    let count = match packet::append_udp_packets(out, &datagram, DEFAULT_MTU) {
        Ok(n) => n,
        Err(e) => {
            log::debug!("réponse UDP {from} -> {to} abandonnée : {e}");
            Stats::count(&shared.stats.dropped);
            return false;
        }
    };
    addrs.clear();
    addrs.resize(count, Address::network(if_idx, 0, true));
    match shared.sink.send(out, addrs) {
        Ok(()) => true,
        Err(e) => {
            log::debug!("injection UDP vers {to} : {e}");
            Stats::count(&shared.stats.errors);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{checksums_valid, parse, tests::sa, Proto};
    use crate::shared::test_util::shared_with;

    #[test]
    fn idle_expiry_boundaries() {
        let idle = Duration::from_secs(180);
        assert_eq!(idle_remaining(0, 0, idle), Some(idle));
        assert_eq!(
            idle_remaining(1_000, 100_000, idle),
            Some(Duration::from_millis(81_000))
        );
        assert_eq!(
            idle_remaining(0, 179_999, idle),
            Some(Duration::from_millis(1))
        );
        assert_eq!(idle_remaining(0, 180_000, idle), None);
        assert_eq!(idle_remaining(0, 500_000, idle), None);
        // Horloge qui « recule » : pas d'expiration.
        assert_eq!(idle_remaining(10_000, 5_000, idle), Some(idle));
    }

    /// Serveur d'écho UDP local ; renvoie son adresse.
    async fn echo_server() -> SocketAddrV4 {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let SocketAddr::V4(addr) = sock.local_addr().unwrap() else {
            unreachable!("IPv4 attendu");
        };
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                let _ = sock.send_to(&buf[..n], peer).await;
            }
        });
        addr
    }

    async fn wait_for_packets(
        sink: &crate::shared::test_util::MockSink,
        min: usize,
    ) -> Vec<(Vec<u8>, Vec<Address>)> {
        for _ in 0..200 {
            {
                let sent = sink.sent.lock().unwrap();
                if sent.len() >= min {
                    return sent.clone();
                }
            }
            sleep(Duration::from_millis(10)).await;
        }
        panic!("aucune réponse injectée");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn udp_roundtrip_builds_and_injects_reply() {
        let (shared, sink) = shared_with(Ipv4Addr::new(192, 168, 137, 1), 24, 8229);
        shared.set_hotspot_if(Some(7));
        let echo = echo_server().await;
        let phone = sa(192, 168, 137, 50, 41000);

        forward(&shared, phone, echo, b"ping");
        assert_eq!(shared.udp.len(), 1);

        let sent = wait_for_packets(&sink, 1).await;
        let (bytes, addrs) = &sent[0];
        assert_eq!(addrs.len(), 1);
        assert!(addrs[0].outbound());
        assert_eq!(addrs[0].if_idx(), 7);
        assert_eq!(addrs[0].sub_if_idx(), 0);
        let info = parse(bytes).unwrap();
        assert_eq!(info.proto, Proto::Udp);
        assert_eq!(info.src, echo);
        assert_eq!(info.dst, phone);
        assert_eq!(info.udp_payload(bytes), b"ping");
        assert!(checksums_valid(bytes, &info));
        assert_eq!(bytes[8], 64);

        let snap = shared.stats.snapshot(0, shared.udp.len());
        assert_eq!(snap.total.up_bytes, 4);
        assert_eq!(snap.total.down_bytes, 4);
        assert_eq!(snap.packets.udp_back, 1);
        shared.signal_stop();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn large_reply_is_fragmented() {
        let (shared, sink) = shared_with(Ipv4Addr::new(192, 168, 137, 1), 24, 8229);
        shared.set_hotspot_if(Some(3));
        let echo = echo_server().await;
        let phone = sa(192, 168, 137, 51, 5000);

        let payload: Vec<u8> = (0..3000).map(|i| (i % 253) as u8).collect();
        forward(&shared, phone, echo, &payload);

        let sent = wait_for_packets(&sink, 1).await;
        let (bytes, addrs) = &sent[0];
        assert_eq!(addrs.len(), 3, "3008 octets UDP -> 3 fragments de MTU 1500");
        let mut off = 0;
        let mut reassembled = Vec::new();
        while off < bytes.len() {
            let len = packet::packet_len(&bytes[off..]).unwrap();
            assert!(len <= DEFAULT_MTU);
            reassembled.extend_from_slice(&bytes[off + 20..off + len]);
            off += len;
        }
        assert_eq!(&reassembled[8..], &payload[..]);
        shared.signal_stop();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reply_is_dropped_without_hotspot_interface() {
        let (shared, sink) = shared_with(Ipv4Addr::new(192, 168, 137, 1), 24, 8229);
        let echo = echo_server().await;
        forward(&shared, sa(192, 168, 137, 52, 6000), echo, b"x");
        sleep(Duration::from_millis(200)).await;
        assert!(sink.sent.lock().unwrap().is_empty());
        assert_eq!(shared.stats.snapshot(0, 0).packets.dropped, 1);
        shared.signal_stop();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn one_session_per_client_regardless_of_destination() {
        let (shared, _sink) = shared_with(Ipv4Addr::new(192, 168, 137, 1), 24, 8229);
        let e1 = echo_server().await;
        let e2 = echo_server().await;
        let phone = sa(192, 168, 137, 53, 7000);
        forward(&shared, phone, e1, b"a");
        forward(&shared, phone, e2, b"b");
        assert_eq!(shared.udp.len(), 1);
        forward(&shared, sa(192, 168, 137, 53, 7001), e1, b"c");
        assert_eq!(shared.udp.len(), 2);
        shared.signal_stop();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocked_device_is_not_forwarded() {
        let (shared, sink) = shared_with(Ipv4Addr::new(192, 168, 137, 1), 24, 8229);
        shared.set_hotspot_if(Some(7));
        let echo = echo_server().await;
        let phone = sa(192, 168, 137, 54, 8000);
        let mut policy = Policy::default();
        policy.blocked.insert(*phone.ip());
        shared.set_policy(policy);
        forward(&shared, phone, echo, b"x");
        assert_eq!(shared.udp.len(), 0, "aucune session ouverte");
        assert_eq!(shared.stats.snapshot(0, 0).packets.dropped, 1);
        sleep(Duration::from_millis(100)).await;
        assert!(sink.sent.lock().unwrap().is_empty());
        shared.signal_stop();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn session_closes_when_device_becomes_blocked() {
        let (shared, sink) = shared_with(Ipv4Addr::new(192, 168, 137, 1), 24, 8229);
        shared.set_hotspot_if(Some(7));
        let echo = echo_server().await;
        let phone = sa(192, 168, 137, 55, 8001);
        forward(&shared, phone, echo, b"a");
        wait_for_packets(&sink, 1).await;

        let session = Arc::clone(&shared.udp.sessions.get(&phone).unwrap());
        let mut policy = Policy::default();
        policy.blocked.insert(*phone.ip());
        shared.set_policy(policy);
        // Une réponse tardive arrive : elle est abandonnée et la session fermée.
        session
            .sender
            .send_to(b"late", SocketAddr::V4(echo))
            .unwrap();
        for _ in 0..200 {
            if shared.udp.is_empty() {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
        assert!(shared.udp.is_empty());
        assert_eq!(
            sink.sent.lock().unwrap().len(),
            1,
            "réponse tardive non injectée"
        );
        shared.signal_stop();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rate_limit_polices_both_directions() {
        let (shared, sink) = shared_with(Ipv4Addr::new(192, 168, 137, 1), 24, 8229);
        shared.set_hotspot_if(Some(7));
        let echo = echo_server().await;
        let phone = sa(192, 168, 137, 56, 8002);
        let mut policy = Policy::default();
        policy
            .limits
            .insert(*phone.ip(), crate::ratelimit::MIN_CAPACITY);
        shared.set_policy(policy);

        // Montant : 16 Kio de rafale, le paquet suivant est abandonné.
        let big = vec![0u8; 10_000];
        forward(&shared, phone, echo, &big);
        wait_for_packets(&sink, 1).await;
        forward(&shared, phone, echo, &big);
        let snap = shared.stats.snapshot(0, 0);
        assert_eq!(snap.total.up_bytes, 10_000);
        assert_eq!(snap.packets.dropped, 1);

        // Descendant : seau séparé, mis en dette (≥ 1 s à rembourser) ; la réponse à un
        // petit envoi (montant encore possible) est abandonnée.
        let rate = crate::ratelimit::MIN_CAPACITY;
        let ip = *phone.ip();
        shared
            .limiter
            .reserve(ip, Direction::Down, rate, 2 * rate, Instant::now());
        forward(&shared, phone, echo, b"ok");
        sleep(Duration::from_millis(300)).await;
        let snap = shared.stats.snapshot(0, 0);
        assert_eq!(snap.total.up_bytes, 10_002);
        assert_eq!(
            snap.total.down_bytes, 10_000,
            "réponse au-delà de la limite abandonnée"
        );
        assert_eq!(snap.packets.dropped, 2);
        assert_eq!(sink.sent.lock().unwrap().len(), 1);
        shared.signal_stop();
    }
}
