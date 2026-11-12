//! Politique appliquée au trafic des appareils : blocage, limites de débit, isolation et DNS
//! (résolveur imposé, bloqueur de publicités).
//!
//! La politique est une valeur immuable : `Engine::set_policy` la remplace d'un bloc.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

/// Politique appliquée au trafic des appareils. Remplacée d'un bloc par `Engine::set_policy`.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    /// Appareils sans accès à internet : tout paquet relayé est abandonné.
    pub blocked: HashSet<Ipv4Addr>,
    /// Débit maximal par appareil, en octets/s, appliqué séparément à chaque sens. Une valeur
    /// inférieure à [`crate::ratelimit::MIN_RATE`] (0 compris) est relevée à ce minimum.
    pub limits: HashMap<Ipv4Addr, u64>,
    /// Isolation : abandonne le trafic relayé vers les réseaux privés/locaux
    /// (10/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10, multicast 224/4).
    pub isolate: bool,
    pub dns: DnsPolicy,
}

/// Politique DNS.
#[derive(Clone, Debug, Default)]
pub struct DnsPolicy {
    /// Résolveur imposé ; `None` = laisser passer vers le DNS de Windows.
    pub upstream: Option<Ipv4Addr>,
    /// Domaines bloqués (bloqueur de publicités) ; `None` = aucun blocage.
    pub blocklist: Option<Arc<Blocklist>>,
}

impl Policy {
    /// L'appareil `ip` est-il privé d'accès à internet ?
    pub fn is_blocked(&self, ip: Ipv4Addr) -> bool {
        self.blocked.contains(&ip)
    }

    /// Débit maximal de l'appareil `ip` (octets/s), s'il est limité.
    pub fn limit(&self, ip: Ipv4Addr) -> Option<u64> {
        self.limits.get(&ip).copied()
    }

    /// Le trafic relayé vers `dst` doit-il être abandonné (isolation) ?
    pub fn drops_destination(&self, dst: Ipv4Addr) -> bool {
        self.isolate && is_private_or_local(dst)
    }

    /// Le nom `domain` est-il bloqué par le bloqueur de publicités ?
    pub fn blocks_domain(&self, domain: &str) -> bool {
        self.dns
            .blocklist
            .as_ref()
            .is_some_and(|b| b.contains(domain))
    }
}

/// Adresse privée ou locale : 10/8, 172.16/12, 192.168/16, 169.254/16 (lien local),
/// 100.64/10 (CGNAT) et multicast 224/4.
pub fn is_private_or_local(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    a == 10
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 169 && b == 254)
        || (a == 100 && (64..=127).contains(&b))
        || (224..=239).contains(&a)
}

/// Noms d'hôtes locaux présents dans les fichiers « hosts », jamais bloqués.
const IGNORED_NAMES: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
];

/// Longueur maximale d'un nom de domaine textuel.
const MAX_DOMAIN_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

/// Ensemble de domaines bloqués ; un domaine est bloqué si lui ou l'un de ses parents l'est.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Blocklist {
    /// Domaines en minuscules, sans point final, d'au moins deux étiquettes.
    domains: HashSet<Box<str>>,
}

impl fmt::Debug for Blocklist {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Blocklist({} domaines)", self.domains.len())
    }
}

/// Normalise une entrée de liste ; `None` si ce n'est pas un domaine à bloquer.
///
/// Les noms d'une seule étiquette (`com`, `lan`…) sont refusés : une telle entrée bloquerait
/// un domaine de premier niveau entier.
fn normalize_entry(token: &str) -> Option<Box<str>> {
    let token = token.strip_prefix("*.").unwrap_or(token);
    let token = token.strip_suffix('.').unwrap_or(token);
    if token.is_empty() || token.len() > MAX_DOMAIN_LEN || !token.contains('.') {
        return None;
    }
    if token.parse::<IpAddr>().is_ok() {
        return None;
    }
    let valid_labels = token.split('.').all(|label| {
        (1..=MAX_LABEL_LEN).contains(&label.len())
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    if !valid_labels {
        return None;
    }
    let lower = token.to_ascii_lowercase();
    if IGNORED_NAMES.contains(&lower.as_str()) {
        return None;
    }
    Some(lower.into_boxed_str())
}

impl Blocklist {
    /// Format « hosts » (`0.0.0.0 domaine`, `127.0.0.1 domaine`, commentaires `#`)
    /// et format « une ligne = un domaine ». Ignore localhost & co.
    ///
    /// Une ligne « hosts » peut porter plusieurs noms ; une ligne sans adresse IP n'est retenue
    /// que si elle ne contient qu'un seul mot. Les entrées invalides sont ignorées.
    pub fn parse(text: &str) -> Blocklist {
        let mut domains = HashSet::new();
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or_default();
            let mut tokens = line.split_whitespace();
            let Some(first) = tokens.next() else {
                continue;
            };
            if first.parse::<IpAddr>().is_ok() {
                domains.extend(tokens.filter_map(normalize_entry));
            } else if tokens.next().is_none() {
                domains.extend(normalize_entry(first));
            }
        }
        Blocklist { domains }
    }

    /// Nombre de domaines de la liste.
    pub fn len(&self) -> usize {
        self.domains.len()
    }

    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    /// `ads.example.com` est bloqué si `example.com` est dans la liste. Insensible à la casse,
    /// ignore un point final.
    pub fn contains(&self, domain: &str) -> bool {
        if self.domains.is_empty() {
            return false;
        }
        let domain = domain.strip_suffix('.').unwrap_or(domain);
        let lower;
        let mut rest = if domain.bytes().any(|b| b.is_ascii_uppercase()) {
            lower = domain.to_ascii_lowercase();
            lower.as_str()
        } else {
            domain
        };
        loop {
            if self.domains.contains(rest) {
                return true;
            }
            match rest.split_once('.') {
                Some((_, parent)) => rest = parent,
                None => return false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    #[test]
    fn private_ranges_and_boundaries() {
        let private = [
            ip(10, 0, 0, 0),
            ip(10, 255, 255, 255),
            ip(172, 16, 0, 0),
            ip(172, 31, 255, 255),
            ip(192, 168, 0, 1),
            ip(192, 168, 255, 255),
            ip(169, 254, 1, 1),
            ip(100, 64, 0, 0),
            ip(100, 127, 255, 255),
            ip(224, 0, 0, 251),
            ip(239, 255, 255, 250),
        ];
        for a in private {
            assert!(is_private_or_local(a), "{a} devrait être privée");
        }
        let public = [
            ip(9, 255, 255, 255),
            ip(11, 0, 0, 0),
            ip(172, 15, 255, 255),
            ip(172, 32, 0, 0),
            ip(192, 167, 255, 255),
            ip(192, 169, 0, 0),
            ip(169, 253, 255, 255),
            ip(169, 255, 0, 0),
            ip(100, 63, 255, 255),
            ip(100, 128, 0, 0),
            ip(223, 255, 255, 255),
            ip(240, 0, 0, 0),
            ip(8, 8, 8, 8),
            ip(1, 1, 1, 1),
        ];
        for a in public {
            assert!(!is_private_or_local(a), "{a} devrait être publique");
        }
    }

    #[test]
    fn policy_helpers() {
        let mut p = Policy::default();
        assert!(!p.is_blocked(ip(192, 168, 137, 2)));
        assert!(
            !p.drops_destination(ip(192, 168, 1, 1)),
            "isolation désactivée"
        );
        assert!(!p.blocks_domain("ads.example.com"), "pas de liste");
        p.blocked.insert(ip(192, 168, 137, 2));
        p.limits.insert(ip(192, 168, 137, 3), 1000);
        p.isolate = true;
        p.dns.blocklist = Some(Arc::new(Blocklist::parse("example.com")));
        assert!(p.is_blocked(ip(192, 168, 137, 2)));
        assert_eq!(p.limit(ip(192, 168, 137, 3)), Some(1000));
        assert_eq!(p.limit(ip(192, 168, 137, 2)), None);
        assert!(p.drops_destination(ip(192, 168, 1, 1)));
        assert!(!p.drops_destination(ip(8, 8, 8, 8)));
        assert!(p.blocks_domain("ads.example.com"));
        assert!(!p.blocks_domain("example.org"));
    }

    #[test]
    fn parses_hosts_format() {
        let text = "\u{feff}# StevenBlack\r\n\
                    127.0.0.1 localhost\r\n\
                    127.0.0.1 localhost.localdomain\r\n\
                    255.255.255.255 broadcasthost\r\n\
                    ::1 localhost ip6-localhost ip6-loopback\r\n\
                    0.0.0.0 0.0.0.0\r\n\
                    \r\n\
                    0.0.0.0 ads.example.com # commentaire\r\n\
                    0.0.0.0\tTracker.Example.NET  metrics.example.org\r\n\
                    127.0.0.1 doubleclick.net.\r\n";
        let b = Blocklist::parse(text);
        assert_eq!(b.len(), 4, "{b:?}");
        assert!(b.contains("ads.example.com"));
        assert!(b.contains("tracker.example.net"));
        assert!(b.contains("metrics.example.org"));
        assert!(b.contains("doubleclick.net"));
        assert!(!b.contains("localhost"));
        assert!(!b.contains("localhost.localdomain"));
        assert!(!b.contains("example.com"), "le parent n'est pas bloqué");
    }

    #[test]
    fn parses_plain_domain_list() {
        let b = Blocklist::parse("example.com\n  *.ads.test.org  \nfoo bar.com\n#x.com\ncom\n");
        assert!(b.contains("example.com"));
        assert!(b.contains("ads.test.org"), "préfixe « *. » accepté");
        assert!(
            !b.contains("bar.com"),
            "ligne de plusieurs mots sans IP ignorée"
        );
        assert!(!b.contains("x.com"), "commentaire");
        assert!(
            !b.contains("com"),
            "domaine de premier niveau jamais bloqué"
        );
        assert_eq!(b.len(), 2);
    }

    #[test]
    fn rejects_invalid_entries() {
        for bad in [
            "0.0.0.0 bad..dots.com",
            "0.0.0.0 bang!.com",
            "0.0.0.0 é.example.com",
            "0.0.0.0 1.2.3.4",
            "0.0.0.0 .",
            "0.0.0.0 .example.com",
            "||ads.example.com^",
        ] {
            let b = Blocklist::parse(bad);
            assert!(b.is_empty(), "{bad} : {b:?}");
        }
        // Tiret et soulignement sont admis (noms réels de listes publiques).
        assert_eq!(Blocklist::parse("0.0.0.0 a-b_c.example.com").len(), 1);
        let long_label = format!("0.0.0.0 {}.com", "a".repeat(64));
        assert!(Blocklist::parse(&long_label).is_empty());
        // 253 caractères : accepté ; 254 : refusé.
        let name = |n: usize| format!("0.0.0.0 {}{}.com", "abcdefghi.".repeat(24), "x".repeat(n));
        assert_eq!(Blocklist::parse(&name(9)).len(), 1);
        assert!(Blocklist::parse(&name(10)).is_empty());
    }

    #[test]
    fn contains_matches_parents_case_and_trailing_dot() {
        let b = Blocklist::parse("0.0.0.0 example.com\n0.0.0.0 track.co.uk");
        assert!(b.contains("example.com"));
        assert!(b.contains("EXAMPLE.com."));
        assert!(b.contains("a.b.c.ads.Example.Com"));
        assert!(
            !b.contains("notexample.com"),
            "suffixe sans frontière d'étiquette"
        );
        assert!(!b.contains("example.com.evil.net"));
        assert!(!b.contains("com"));
        assert!(!b.contains("co.uk"));
        assert!(b.contains("x.track.co.uk"));
        assert!(!b.contains(""));
        assert!(!b.contains("."));
        assert!(!b.contains(".."));
        assert!(!Blocklist::default().contains("example.com"));
        assert!(Blocklist::default().is_empty());
    }
}
