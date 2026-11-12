//! Limitation de débit : un seau à jetons par appareil et par sens, partagé par toutes les
//! connexions de l'appareil.
//!
//! - lissage (proxy TCP) : [`TokenBucket::reserve`] consomme toujours et renvoie l'attente à
//!   respecter avant d'envoyer (le seau peut s'endetter) ;
//! - police (UDP) : [`TokenBucket::try_take`] refuse le paquet faute de jetons.
//!
//! L'horloge est injectée (`now`) : toute la logique est testable sans réseau ni attente.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// Capacité minimale d'un seau (rafale autorisée), en octets.
pub const MIN_CAPACITY: u64 = 16 * 1024;
/// Débit minimal applicable (octets/s) ; une limite inférieure (0 compris) est relevée.
pub const MIN_RATE: u64 = 1024;
/// Attente maximale renvoyée par [`TokenBucket::reserve`].
pub const MAX_WAIT: Duration = Duration::from_secs(60);

/// Sens du trafic. `Up` = appareil -> internet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Direction {
    Up,
    Down,
}

/// Seau à jetons (un jeton = un octet). Capacité ≈ 1 s de débit, au moins [`MIN_CAPACITY`].
#[derive(Clone, Debug)]
pub struct TokenBucket {
    rate: u64,
    capacity: f64,
    /// Jetons disponibles ; négatif = dette (lissage).
    tokens: f64,
    last: Instant,
}

fn effective_rate(rate: u64) -> u64 {
    rate.max(MIN_RATE)
}

fn capacity_for(rate: u64) -> f64 {
    rate.max(MIN_CAPACITY) as f64
}

impl TokenBucket {
    /// Seau plein au débit `rate` (octets/s).
    pub fn new(rate: u64, now: Instant) -> Self {
        let rate = effective_rate(rate);
        let capacity = capacity_for(rate);
        Self {
            rate,
            capacity,
            tokens: capacity,
            last: now,
        }
    }

    /// Débit effectif (octets/s).
    pub fn rate(&self) -> u64 {
        self.rate
    }

    /// Capacité (octets).
    pub fn capacity(&self) -> u64 {
        self.capacity as u64
    }

    /// Jetons disponibles à l'instant `now` (négatif en cas de dette).
    pub fn available(&mut self, now: Instant) -> f64 {
        self.refill(now);
        self.tokens
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last);
        // Une horloge qui « recule » ne crée ni ne retire de jetons.
        self.last = self.last.max(now);
        self.tokens = (self.tokens + elapsed.as_secs_f64() * self.rate as f64).min(self.capacity);
    }

    /// Change le débit en conservant les jetons acquis (bornés par la nouvelle capacité) :
    /// s'applique immédiatement aux connexions en cours.
    pub fn set_rate(&mut self, rate: u64, now: Instant) {
        let rate = effective_rate(rate);
        if rate == self.rate {
            return;
        }
        self.refill(now);
        self.rate = rate;
        self.capacity = capacity_for(rate);
        self.tokens = self.tokens.min(self.capacity);
    }

    /// Lissage : consomme `n` octets (dette permise) et renvoie l'attente à respecter avant
    /// de les envoyer (zéro si les jetons étaient disponibles), bornée par [`MAX_WAIT`].
    pub fn reserve(&mut self, n: u64, now: Instant) -> Duration {
        self.refill(now);
        self.tokens -= n as f64;
        if self.tokens >= 0.0 {
            return Duration::ZERO;
        }
        Duration::try_from_secs_f64(-self.tokens / self.rate as f64)
            .map_or(MAX_WAIT, |d| d.min(MAX_WAIT))
    }

    /// Police : `true` si `n` octets passent (et sont consommés), `false` sinon (rien n'est
    /// consommé). Un paquet plus gros que la capacité ne passe que si le seau est plein.
    pub fn try_take(&mut self, n: u64, now: Instant) -> bool {
        self.refill(now);
        let n = n as f64;
        if self.tokens >= n.min(self.capacity) {
            self.tokens -= n;
            true
        } else {
            false
        }
    }
}

/// Seaux de tous les appareils limités.
#[derive(Default)]
pub struct RateLimiter {
    buckets: DashMap<(Ipv4Addr, Direction), Mutex<TokenBucket>>,
}

impl RateLimiter {
    /// Applique `f` au seau `(ip, dir)` (créé plein au besoin), mis au débit `rate`.
    fn with_bucket<T>(
        &self,
        ip: Ipv4Addr,
        dir: Direction,
        rate: u64,
        now: Instant,
        f: impl FnOnce(&mut TokenBucket) -> T,
    ) -> T {
        let apply = |m: &Mutex<TokenBucket>| {
            let mut bucket = m.lock().unwrap_or_else(PoisonError::into_inner);
            bucket.set_rate(rate, now);
            f(&mut bucket)
        };
        let key = (ip, dir);
        if let Some(m) = self.buckets.get(&key) {
            return apply(&m);
        }
        let m = self
            .buckets
            .entry(key)
            .or_insert_with(|| Mutex::new(TokenBucket::new(rate, now)));
        apply(&m)
    }

    /// Lissage : attente avant d'envoyer `n` octets de l'appareil `ip` dans le sens `dir`.
    pub fn reserve(
        &self,
        ip: Ipv4Addr,
        dir: Direction,
        rate: u64,
        n: u64,
        now: Instant,
    ) -> Duration {
        self.with_bucket(ip, dir, rate, now, |b| b.reserve(n, now))
    }

    /// Police : `n` octets de l'appareil `ip` peuvent-ils passer dans le sens `dir` ?
    pub fn try_take(&self, ip: Ipv4Addr, dir: Direction, rate: u64, n: u64, now: Instant) -> bool {
        self.with_bucket(ip, dir, rate, now, |b| b.try_take(n, now))
    }

    /// Oublie les seaux des appareils qui ne sont plus limités.
    pub fn retain(&self, limits: &HashMap<Ipv4Addr, u64>) {
        self.buckets.retain(|(ip, _), _| limits.contains_key(ip));
    }

    /// Nombre de seaux (appareil, sens) existants.
    pub fn len(&self) -> usize {
        self.buckets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KIB: u64 = 1024;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn capacity_is_one_second_with_minimum() {
        let t = Instant::now();
        assert_eq!(TokenBucket::new(100 * KIB, t).capacity(), 100 * KIB);
        assert_eq!(TokenBucket::new(4 * KIB, t).capacity(), MIN_CAPACITY);
        let zero = TokenBucket::new(0, t);
        assert_eq!(zero.rate(), MIN_RATE, "débit nul relevé au minimum");
        assert_eq!(zero.capacity(), MIN_CAPACITY);
    }

    #[test]
    fn police_allows_burst_then_refills_with_time() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(32 * KIB, t0);
        // Rafale initiale : toute la capacité.
        assert!(b.try_take(20 * KIB, t0));
        assert!(b.try_take(12 * KIB, t0));
        assert!(!b.try_take(1, t0), "seau vide");
        // 100 ms à 32 Kio/s = 3276,8 octets.
        assert!(b.try_take(3276, t0 + ms(100)));
        assert!(!b.try_take(2, t0 + ms(100)));
        // Le remplissage est plafonné à la capacité.
        assert_eq!(
            b.available(t0 + Duration::from_secs(3600)),
            (32 * KIB) as f64
        );
    }

    #[test]
    fn police_refusal_consumes_nothing_and_oversize_needs_full_bucket() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(MIN_CAPACITY, t0);
        assert!(b.try_take(10 * KIB, t0));
        let before = b.available(t0);
        assert!(!b.try_take(10 * KIB, t0));
        assert_eq!(b.available(t0), before);
        // Datagramme de 40 Kio > capacité : refusé tant que le seau n'est pas plein…
        assert!(!b.try_take(40 * KIB, t0 + ms(500)));
        // …accepté une fois plein, puis dette remboursée avant le paquet suivant.
        let full = t0 + Duration::from_secs(2);
        assert!(b.try_take(40 * KIB, full));
        assert!(!b.try_take(1, full + Duration::from_secs(1)));
        assert!(b.try_take(1, full + ms(1550)));
    }

    #[test]
    fn shaping_returns_waits_that_respect_the_rate() {
        let t0 = Instant::now();
        let rate = 64 * KIB;
        let mut b = TokenBucket::new(rate, t0);
        // La capacité (1 s) part sans attente.
        assert_eq!(b.reserve(64 * KIB, t0), Duration::ZERO);
        // 32 Kio de plus : 0,5 s d'attente ; puis 32 Kio de plus : 1 s cumulée.
        assert_eq!(b.reserve(32 * KIB, t0), ms(500));
        assert_eq!(b.reserve(32 * KIB, t0), Duration::from_secs(1));
        // Après 1 s, la dette est remboursée.
        assert_eq!(b.reserve(0, t0 + Duration::from_secs(1)), Duration::ZERO);
        // Débit moyen sur une longue durée : 100 envois de 8 Kio à cadence libre.
        let mut now = t0 + Duration::from_secs(1);
        let start = now;
        for _ in 0..100 {
            now += b.reserve(8 * KIB, now);
        }
        let elapsed = now - start;
        // Seau vide au départ (dette tout juste remboursée) : 800 Kio à 64 Kio/s = 12,5 s.
        let expected = 12.5;
        assert!(
            (elapsed.as_secs_f64() - expected).abs() < 0.01,
            "{elapsed:?}"
        );
    }

    #[test]
    fn wait_is_bounded() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(MIN_RATE, t0);
        assert_eq!(b.reserve(u64::MAX, t0), MAX_WAIT);
    }

    #[test]
    fn rate_change_keeps_tokens_and_clamps_to_new_capacity() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(100 * KIB, t0);
        b.set_rate(20 * KIB, t0);
        assert_eq!(b.rate(), 20 * KIB);
        assert_eq!(
            b.available(t0),
            (20 * KIB) as f64,
            "plafonné à la nouvelle capacité"
        );
        assert!(b.try_take(20 * KIB, t0));
        // Nouveau débit appliqué au remplissage.
        b.set_rate(40 * KIB, t0);
        assert_eq!(b.available(t0 + ms(250)), (10 * KIB) as f64);
        // Même débit : sans effet.
        b.set_rate(40 * KIB, t0 + ms(250));
        assert_eq!(b.rate(), 40 * KIB);
    }

    #[test]
    fn clock_going_backwards_is_harmless() {
        let t0 = Instant::now() + Duration::from_secs(10);
        let mut b = TokenBucket::new(MIN_CAPACITY, t0);
        assert!(b.try_take(MIN_CAPACITY, t0));
        assert!(!b.try_take(1, t0 - Duration::from_secs(5)));
        assert_eq!(b.available(t0 - Duration::from_secs(5)), 0.0);
        assert!(b.try_take(1024, t0 + ms(100)));
    }

    #[test]
    fn limiter_shares_buckets_per_device_and_direction() {
        let t0 = Instant::now();
        let a = Ipv4Addr::new(192, 168, 137, 2);
        let c = Ipv4Addr::new(192, 168, 137, 3);
        let l = RateLimiter::default();
        assert!(l.try_take(a, Direction::Up, MIN_CAPACITY, MIN_CAPACITY, t0));
        // Même appareil, même sens : seau partagé (épuisé).
        assert!(!l.try_take(a, Direction::Up, MIN_CAPACITY, 1, t0));
        // Autre sens ou autre appareil : seaux distincts.
        assert!(l.try_take(a, Direction::Down, MIN_CAPACITY, MIN_CAPACITY, t0));
        assert!(l.try_take(c, Direction::Up, MIN_CAPACITY, 1, t0));
        assert_eq!(l.len(), 3);
        // Le lissage voit la dette de la police (même seau).
        assert_eq!(
            l.reserve(a, Direction::Up, MIN_CAPACITY, 8 * KIB, t0),
            ms(500)
        );

        // Changement de limite appliqué au seau existant.
        assert!(!l.try_take(a, Direction::Down, 64 * KIB, 4 * KIB, t0));
        assert!(l.try_take(a, Direction::Down, 64 * KIB, 4 * KIB, t0 + ms(100)));

        let mut limits = HashMap::new();
        limits.insert(c, 1);
        l.retain(&limits);
        assert_eq!(l.len(), 1);
        l.retain(&HashMap::new());
        assert!(l.is_empty());
    }
}
