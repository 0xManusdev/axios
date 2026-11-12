//! Proxy TCP transparent : accepte les connexions du téléphone (réinjectées vers
//! `gateway:tcp_port`), ouvre la connexion vers la destination d'origine (table NAT) et
//! relaie les octets dans les deux sens avec demi-fermeture.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::time::{sleep, timeout};

use crate::ratelimit::Direction;
use crate::shared::Shared;
use crate::stats::Stats;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const SWEEP_INTERVAL: Duration = Duration::from_secs(5);
const LOG_INTERVAL: Duration = Duration::from_secs(10);
const RELAY_BUF_LEN: usize = 32 * 1024;
/// Taille des lectures d'un appareil limité : des envois plus petits lissent mieux le débit.
const LIMITED_CHUNK_LEN: usize = 8 * 1024;

/// Boucle d'acceptation ; se termine à l'arrêt du moteur.
pub async fn serve(listener: TcpListener, shared: Arc<Shared>) {
    let mut stop = shared.stop_signal();
    loop {
        let accepted = tokio::select! {
            r = listener.accept() => r,
            _ = stop.changed() => return,
        };
        match accepted {
            Ok((stream, SocketAddr::V4(peer))) => {
                tokio::spawn(handle(Arc::clone(&shared), stream, peer));
            }
            Ok(_) => {}
            Err(e) => {
                // Typiquement trop de descripteurs ouverts : temporiser pour ne pas boucler.
                log::warn!("accept du proxy TCP : {e}");
                Stats::count(&shared.stats.errors);
                sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

/// Tâche périodique : purge de la table NAT et journal de synthèse.
pub async fn maintenance(shared: Arc<Shared>) {
    let mut stop = shared.stop_signal();
    let mut since_log = Duration::ZERO;
    loop {
        tokio::select! {
            () = sleep(SWEEP_INTERVAL) => {}
            _ = stop.changed() => return,
        }
        shared.nat.sweep(Instant::now());
        since_log += SWEEP_INTERVAL;
        if since_log >= LOG_INTERVAL {
            since_log = Duration::ZERO;
            let s = shared
                .stats
                .snapshot(shared.active_tcp.load(Relaxed), shared.udp.len());
            log::debug!(
                "paquets {:?} | tcp actifs {} | udp actifs {} | nat {} | descendant {} montant {}",
                s.packets,
                s.active_tcp,
                s.active_udp,
                shared.nat.len(),
                s.total.down_bytes,
                s.total.up_bytes
            );
        }
    }
}

struct ActiveGuard<'a>(&'a Shared);

impl<'a> ActiveGuard<'a> {
    fn new(shared: &'a Shared) -> Self {
        shared.active_tcp.fetch_add(1, Relaxed);
        Self(shared)
    }
}

impl Drop for ActiveGuard<'_> {
    fn drop(&mut self) {
        self.0.active_tcp.fetch_sub(1, Relaxed);
    }
}

async fn handle(shared: Arc<Shared>, client: TcpStream, peer: SocketAddrV4) {
    if !shared.subnet.contains(*peer.ip()) {
        log::debug!("connexion refusée : {peer} hors du réseau du point d'accès");
        Stats::count(&shared.stats.dropped);
        return;
    }
    if shared.policy().is_blocked(*peer.ip()) {
        log::debug!("connexion refusée : {peer} bloqué");
        Stats::count(&shared.stats.dropped);
        return;
    }
    let Some(claim) = shared.nat.claim(peer) else {
        log::debug!("connexion refusée : {peer} sans entrée NAT");
        Stats::count(&shared.stats.dropped);
        return;
    };
    let _active = ActiveGuard::new(&shared);

    let result = async {
        let upstream = timeout(CONNECT_TIMEOUT, TcpStream::connect(claim.dst))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "délai de connexion dépassé"))??;
        let _ = client.set_nodelay(true);
        let _ = upstream.set_nodelay(true);
        relay(&shared, peer, client, upstream).await
    }
    .await;

    if let Err(e) = result {
        log::debug!("connexion {peer} -> {} terminée : {e}", claim.dst);
    }
    shared.nat.close(peer, claim, Instant::now());
}

async fn relay(
    shared: &Shared,
    peer: SocketAddrV4,
    client: TcpStream,
    upstream: TcpStream,
) -> io::Result<()> {
    let ip = *peer.ip();
    // Abonnement avant la première vérification : aucun changement ne peut être manqué.
    let mut policy_rx = shared.policy_watch();
    let (client_r, client_w) = client.into_split();
    let (up_r, up_w) = upstream.into_split();
    // `try_join!` : la première erreur interrompt l'autre sens et ferme tout ; une fin de
    // flux normale (EOF) ne ferme que le sens correspondant (demi-fermeture).
    let up = DeviceFlow::new(shared, ip, Direction::Up);
    let down = DeviceFlow::new(shared, ip, Direction::Down);
    let transfer = async {
        tokio::try_join!(pump(client_r, up_w, &up), pump(up_r, client_w, &down),).map(|_| ())
    };
    tokio::select! {
        r = transfer => r,
        () = until_blocked(shared, ip, &mut policy_rx) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "appareil bloqué",
        )),
    }
}

/// Se termine quand l'appareil `ip` devient bloqué (les flux sont alors fermés).
async fn until_blocked(shared: &Shared, ip: Ipv4Addr, rx: &mut watch::Receiver<()>) {
    loop {
        if shared.policy().is_blocked(ip) {
            return;
        }
        if rx.changed().await.is_err() {
            // Émetteur disparu (arrêt du moteur) : plus aucun changement à attendre.
            std::future::pending::<()>().await;
        }
    }
}

/// Réglage d'un sens de relais : taille des lectures, limitation de débit et comptage.
trait Flow {
    /// Taille maximale de la prochaine lecture.
    fn chunk_len(&self) -> usize;
    /// Attente imposée avant d'écrire `n` octets (jetons réservés).
    fn delay(&self, n: usize) -> Duration;
    /// `n` octets ont été relayés.
    fn count(&self, n: usize);
}

/// Sens de relais d'un appareil : limite lue dans la politique courante à chaque envoi (un
/// changement de limite s'applique donc aux connexions en cours).
struct DeviceFlow<'a> {
    shared: &'a Shared,
    ip: Ipv4Addr,
    dir: Direction,
}

impl<'a> DeviceFlow<'a> {
    fn new(shared: &'a Shared, ip: Ipv4Addr, dir: Direction) -> Self {
        Self { shared, ip, dir }
    }
}

impl Flow for DeviceFlow<'_> {
    fn chunk_len(&self) -> usize {
        if self.shared.policy().limit(self.ip).is_some() {
            LIMITED_CHUNK_LEN
        } else {
            RELAY_BUF_LEN
        }
    }

    fn delay(&self, n: usize) -> Duration {
        let policy = self.shared.policy();
        self.shared
            .pace(&policy, self.ip, self.dir, n, Instant::now())
    }

    fn count(&self, n: usize) {
        match self.dir {
            Direction::Up => self.shared.stats.add_up(self.ip, n as u64),
            Direction::Down => self.shared.stats.add_down(self.ip, n as u64),
        }
    }
}

/// Copie `r` vers `w` en respectant le débit de `flow` (attente des jetons avant d'écrire),
/// compte les octets, puis propage la fermeture d'écriture.
async fn pump<R, W>(mut r: R, mut w: W, flow: &impl Flow) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; RELAY_BUF_LEN];
    loop {
        let len = flow.chunk_len().clamp(1, buf.len());
        let n = r.read(&mut buf[..len]).await?;
        if n == 0 {
            // Demi-fermeture : l'autre extrémité peut encore envoyer.
            w.shutdown().await?;
            return Ok(());
        }
        let wait = flow.delay(n);
        if !wait.is_zero() {
            sleep(wait).await;
        }
        w.write_all(&buf[..n]).await?;
        flow.count(n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;
    use crate::shared::test_util::shared_with;
    use tokio::net::TcpSocket;

    /// Sens de relais de test : lectures de `chunk` octets, attente fixe par envoi.
    struct TestFlow {
        chunk: usize,
        wait: Duration,
        counted: std::sync::atomic::AtomicU64,
        chunks: std::sync::atomic::AtomicU64,
    }

    impl TestFlow {
        fn new(chunk: usize, wait: Duration) -> Self {
            Self {
                chunk,
                wait,
                counted: Default::default(),
                chunks: Default::default(),
            }
        }
    }

    impl Flow for TestFlow {
        fn chunk_len(&self) -> usize {
            self.chunk
        }
        fn delay(&self, n: usize) -> Duration {
            assert!(n <= self.chunk, "lecture plus grande que demandé");
            self.chunks.fetch_add(1, Relaxed);
            self.wait
        }
        fn count(&self, n: usize) {
            self.counted.fetch_add(n as u64, Relaxed);
        }
    }

    #[tokio::test]
    async fn pump_copies_counts_and_half_closes() {
        let (mut a_tx, a_rx) = tokio::io::duplex(1024);
        let (b_tx, mut b_rx) = tokio::io::duplex(1024);
        let flow = TestFlow::new(RELAY_BUF_LEN, Duration::ZERO);
        let counted = &flow.counted;
        let task = pump(a_rx, b_tx, &flow);
        let driver = async {
            a_tx.write_all(b"hello world").await.unwrap();
            a_tx.shutdown().await.unwrap();
            let mut got = Vec::new();
            b_rx.read_to_end(&mut got).await.unwrap(); // EOF propagé
            got
        };
        let (res, got) = tokio::join!(task, driver);
        res.unwrap();
        assert_eq!(got, b"hello world");
        assert_eq!(counted.load(Relaxed), 11);
    }

    /// Serveur TCP d'écho en boucle locale ; renvoie son adresse.
    async fn tcp_echo() -> SocketAddrV4 {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let SocketAddr::V4(addr) = l.local_addr().unwrap() else {
            unreachable!("IPv4 attendu");
        };
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                    let _ = w.shutdown().await;
                });
            }
        });
        addr
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn proxy_relays_through_nat_entry_and_cleans_up() {
        // Réseau de test = 127.0.0.0/8 : le « téléphone » est un client local.
        let (shared, _sink) = shared_with(Ipv4Addr::new(127, 0, 0, 1), 8, 0);
        let upstream = tcp_echo().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, Arc::clone(&shared)));

        // Le client se lie d'abord pour connaître son port, puis « envoie son SYN ».
        let sock = TcpSocket::new_v4().unwrap();
        sock.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let SocketAddr::V4(me) = sock.local_addr().unwrap() else {
            unreachable!("IPv4 attendu");
        };
        shared.nat.register_syn(me, upstream, Instant::now());
        let mut conn = sock.connect(proxy_addr).await.unwrap();

        conn.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        conn.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
        assert_eq!(shared.active_tcp.load(Relaxed), 1);

        conn.shutdown().await.unwrap();
        let mut rest = Vec::new();
        conn.read_to_end(&mut rest).await.unwrap(); // EOF venant de l'amont
        assert!(rest.is_empty());

        for _ in 0..200 {
            if shared.active_tcp.load(Relaxed) == 0 {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(shared.active_tcp.load(Relaxed), 0);
        let s = shared.stats.snapshot(0, 0);
        assert_eq!(s.total.up_bytes, 5);
        assert_eq!(s.total.down_bytes, 5);
        assert_eq!(s.per_device[&Ipv4Addr::LOCALHOST].up_bytes, 5);
        // L'entrée est fermée mais conservée (derniers FIN/ACK) ; plus réclamable.
        assert_eq!(shared.nat.lookup(me), Some(upstream));
        assert!(shared.nat.claim(me).is_none());
        shared.signal_stop();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn proxy_refuses_unknown_peer() {
        let (shared, _sink) = shared_with(Ipv4Addr::new(127, 0, 0, 1), 8, 0);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, Arc::clone(&shared)));

        let mut conn = TcpStream::connect(proxy_addr).await.unwrap();
        let mut buf = Vec::new();
        // Fermée sans donnée (EOF ou réinitialisation).
        let _ = conn.read_to_end(&mut buf).await;
        assert!(buf.is_empty());
        assert_eq!(shared.stats.snapshot(0, 0).packets.dropped, 1);
        shared.signal_stop();
    }

    #[tokio::test(start_paused = true)]
    async fn pump_reads_in_chunks_and_waits_for_tokens() {
        let (mut a_tx, a_rx) = tokio::io::duplex(1024);
        let (b_tx, mut b_rx) = tokio::io::duplex(1024);
        let flow = TestFlow::new(4, Duration::from_millis(100));
        let start = tokio::time::Instant::now();
        let driver = async {
            a_tx.write_all(b"hello world!").await.unwrap();
            a_tx.shutdown().await.unwrap();
            let mut got = Vec::new();
            b_rx.read_to_end(&mut got).await.unwrap();
            got
        };
        let (res, got) = tokio::join!(pump(a_rx, b_tx, &flow), driver);
        res.unwrap();
        assert_eq!(got, b"hello world!");
        assert_eq!(flow.chunks.load(Relaxed), 3, "lectures de 4 octets au plus");
        assert!(start.elapsed() >= Duration::from_millis(300));
        assert_eq!(flow.counted.load(Relaxed), 12);
    }

    #[tokio::test]
    async fn device_flow_follows_current_limit() {
        let (shared, _sink) = shared_with(Ipv4Addr::new(192, 168, 137, 1), 24, 8229);
        let phone = Ipv4Addr::new(192, 168, 137, 50);
        let up = DeviceFlow::new(&shared, phone, Direction::Up);
        let down = DeviceFlow::new(&shared, phone, Direction::Down);
        assert_eq!(up.chunk_len(), RELAY_BUF_LEN);
        assert_eq!(up.delay(1 << 20), Duration::ZERO, "sans limite");

        let mut policy = Policy::default();
        policy.limits.insert(phone, crate::ratelimit::MIN_CAPACITY);
        shared.set_policy(policy);
        assert_eq!(up.chunk_len(), LIMITED_CHUNK_LEN);
        // Rafale d'1 s, puis 8 Kio de plus à 16 Kio/s : ≈ 0,5 s d'attente.
        assert_eq!(up.delay(16 * 1024), Duration::ZERO);
        let wait = up.delay(8 * 1024);
        assert!(
            wait > Duration::from_millis(400) && wait <= Duration::from_millis(500),
            "{wait:?}"
        );
        // L'autre sens a son propre seau.
        assert_eq!(down.delay(16 * 1024), Duration::ZERO);

        up.count(10);
        down.count(20);
        let s = shared.stats.snapshot(0, 0);
        assert_eq!(
            (
                s.per_device[&phone].up_bytes,
                s.per_device[&phone].down_bytes
            ),
            (10, 20)
        );

        // Limite retirée : effet immédiat, seaux oubliés.
        shared.set_policy(Policy::default());
        assert_eq!(up.delay(1 << 20), Duration::ZERO);
        assert!(shared.limiter.is_empty());
    }

    /// Lance le proxy et connecte un client local muni d'une entrée NAT vers un serveur d'écho.
    async fn connected_client(shared: &Arc<Shared>) -> (TcpStream, SocketAddrV4) {
        let upstream = tcp_echo().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, Arc::clone(shared)));
        let sock = TcpSocket::new_v4().unwrap();
        sock.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let SocketAddr::V4(me) = sock.local_addr().unwrap() else {
            unreachable!("IPv4 attendu");
        };
        shared.nat.register_syn(me, upstream, Instant::now());
        (sock.connect(proxy_addr).await.unwrap(), me)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocking_a_device_closes_its_connections() {
        let (shared, _sink) = shared_with(Ipv4Addr::new(127, 0, 0, 1), 8, 0);
        let (mut conn, _me) = connected_client(&shared).await;
        conn.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        conn.read_exact(&mut buf).await.unwrap();
        assert_eq!(shared.active_tcp.load(Relaxed), 1);

        // Bloquer un autre appareil ne change rien.
        let mut other = Policy::default();
        other.blocked.insert(Ipv4Addr::new(127, 0, 0, 9));
        shared.set_policy(other);
        conn.write_all(b"pong").await.unwrap();
        conn.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");

        let mut policy = Policy::default();
        policy.blocked.insert(Ipv4Addr::LOCALHOST);
        shared.set_policy(policy);
        let mut rest = Vec::new();
        // Fermée par le proxy (EOF ou réinitialisation), sans attendre le client.
        let closed = timeout(Duration::from_secs(5), conn.read_to_end(&mut rest)).await;
        assert!(closed.is_ok(), "la connexion aurait dû être fermée");
        for _ in 0..200 {
            if shared.active_tcp.load(Relaxed) == 0 {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(shared.active_tcp.load(Relaxed), 0);
        shared.signal_stop();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn proxy_refuses_blocked_device() {
        let (shared, _sink) = shared_with(Ipv4Addr::new(127, 0, 0, 1), 8, 0);
        let mut policy = Policy::default();
        policy.blocked.insert(Ipv4Addr::LOCALHOST);
        shared.set_policy(policy);
        let (mut conn, me) = connected_client(&shared).await;
        let mut buf = Vec::new();
        let _ = conn.read_to_end(&mut buf).await;
        assert!(buf.is_empty());
        assert_eq!(shared.stats.snapshot(0, 0).packets.dropped, 1);
        // L'entrée NAT n'a pas été réclamée.
        assert!(shared.nat.claim(me).is_some());
        shared.signal_stop();
    }
}
