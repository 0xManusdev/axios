//! Construction de la politique du moteur à partir des réglages, des préférences d'appareils
//! et des appareils présents sur le réseau (correspondance MAC → IP).

use std::{net::Ipv4Addr, sync::Arc};

use pw_engine::{Blocklist, DnsPolicy, Policy};

use crate::{
    devices::{DeviceEntry, DeviceStore},
    settings::{mbps_to_bytes, Settings},
};

/// Appareil présent sur le réseau du point d'accès.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Peer {
    pub ip: Ipv4Addr,
    /// MAC normalisée (`AA:BB:CC:DD:EE:FF`), si connue.
    pub mac: Option<String>,
}

/// Préférences d'un appareil présent : par MAC, sinon par IP.
fn entry_for<'a>(devices: &'a DeviceStore, peer: &Peer) -> Option<&'a DeviceEntry> {
    peer.mac
        .as_deref()
        .and_then(|mac| devices.get(mac))
        .or_else(|| devices.get(&peer.ip.to_string()))
}

/// Politique complète (le moteur la remplace d'un bloc). Les clés sont les IP actuelles.
pub fn build_policy(
    settings: &Settings,
    devices: &DeviceStore,
    peers: &[Peer],
    blocklist: Option<Arc<Blocklist>>,
) -> Policy {
    let mut policy = Policy {
        isolate: settings.isolate,
        dns: DnsPolicy {
            upstream: settings.dns_upstream(),
            blocklist: if settings.ad_block { blocklist } else { None },
        },
        ..Policy::default()
    };
    let mut apply = |ip: Ipv4Addr, entry: Option<&DeviceEntry>, default_limit: Option<f64>| {
        if entry.is_some_and(|e| e.blocked) {
            policy.blocked.insert(ip);
        }
        if let Some(limit) = entry.and_then(|e| e.limit).or(default_limit) {
            policy.limits.insert(ip, mbps_to_bytes(limit));
        }
    };
    for peer in peers {
        apply(peer.ip, entry_for(devices, peer), settings.default_limit);
    }
    // Appareils connus seulement par leur IP et absents pour l'instant : leurs réglages
    // propres s'appliquent dès leur retour.
    for (id, entry) in &devices.entries {
        if let Ok(ip) = id.parse::<Ipv4Addr>() {
            if !peers.iter().any(|p| p.ip == ip) {
                apply(ip, Some(entry), None);
            }
        }
    }
    policy
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::Dns;

    const MAC_A: &str = "AA:BB:CC:DD:EE:01";
    const MAC_B: &str = "AA:BB:CC:DD:EE:02";

    fn ip(n: u8) -> Ipv4Addr {
        Ipv4Addr::new(192, 168, 137, n)
    }

    fn peer(n: u8, mac: Option<&str>) -> Peer {
        Peer {
            ip: ip(n),
            mac: mac.map(str::to_owned),
        }
    }

    #[test]
    fn blocage_et_limites_par_ip() {
        let mut devices = DeviceStore::default();
        devices.set_blocked(MAC_A, true);
        devices.set_limit(MAC_B, Some(2.0));
        devices.set_limit("192.168.137.30", Some(1.0));
        let settings = Settings {
            default_limit: Some(10.0),
            ..Settings::default()
        };
        let peers = [
            peer(10, Some(MAC_A)),
            peer(11, Some(MAC_B)),
            peer(12, None),
            peer(30, None),
        ];
        let p = build_policy(&settings, &devices, &peers, None);
        assert_eq!(p.blocked, [ip(10)].into());
        assert_eq!(p.limits.get(&ip(10)), Some(&1_250_000), "limite par défaut");
        assert_eq!(p.limits.get(&ip(11)), Some(&250_000), "limite propre");
        assert_eq!(p.limits.get(&ip(12)), Some(&1_250_000));
        assert_eq!(p.limits.get(&ip(30)), Some(&125_000), "réglage par IP");
    }

    #[test]
    fn la_mac_suit_l_appareil() {
        let mut devices = DeviceStore::default();
        devices.set_blocked(MAC_A, true);
        let s = Settings::default();
        let before = build_policy(&s, &devices, &[peer(10, Some(MAC_A))], None);
        let after = build_policy(&s, &devices, &[peer(77, Some(MAC_A))], None);
        assert_eq!(before.blocked, [ip(10)].into());
        assert_eq!(after.blocked, [ip(77)].into());
        assert!(after.limits.is_empty(), "sans limite par défaut");
    }

    #[test]
    fn appareil_ip_absent_conserve_ses_reglages() {
        let mut devices = DeviceStore::default();
        devices.set_blocked("192.168.137.40", true);
        let settings = Settings {
            default_limit: Some(5.0),
            ..Settings::default()
        };
        let p = build_policy(&settings, &devices, &[], None);
        assert_eq!(p.blocked, [ip(40)].into());
        assert!(
            p.limits.is_empty(),
            "limite par défaut réservée aux présents"
        );
    }

    #[test]
    fn isolation_dns_et_bloqueur() {
        let list = Arc::new(Blocklist::parse("0.0.0.0 ads.example.com"));
        let mut settings = Settings {
            isolate: true,
            dns: Dns::Cloudflare,
            ..Settings::default()
        };
        let p = build_policy(
            &settings,
            &DeviceStore::default(),
            &[],
            Some(Arc::clone(&list)),
        );
        assert!(p.isolate);
        assert_eq!(p.dns.upstream, Some(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(p.dns.blocklist.is_none(), "bloqueur désactivé");

        settings.ad_block = true;
        let p = build_policy(&settings, &DeviceStore::default(), &[], Some(list));
        assert!(p.blocks_domain("ads.example.com"));
    }
}
