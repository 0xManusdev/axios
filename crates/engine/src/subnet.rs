//! Réseau IPv4 du point d'accès et génération des filtres WinDivert.

use std::net::Ipv4Addr;

use crate::error::EngineError;

/// Réseau IPv4 `adresse/préfixe` (adresse réseau normalisée).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Subnet {
    base: u32,
    mask: u32,
}

impl Subnet {
    /// Construit le réseau contenant `gateway` avec `prefix_len` bits de préfixe (8 à 30).
    pub fn new(gateway: Ipv4Addr, prefix_len: u8) -> Result<Self, EngineError> {
        if !(8..=30).contains(&prefix_len) {
            return Err(EngineError::Config(format!(
                "longueur de préfixe {prefix_len} non prise en charge (8 à 30)"
            )));
        }
        let mask = u32::MAX << (32 - u32::from(prefix_len));
        Ok(Self {
            base: u32::from(gateway) & mask,
            mask,
        })
    }

    /// Adresse du réseau (`N[0]`).
    pub fn network(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.base)
    }

    /// Adresse de diffusion (`N[-1]`).
    pub fn broadcast(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.base | !self.mask)
    }

    /// Première adresse client (`N[2]`, la `.1` étant la passerelle).
    pub fn first_client(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.base + 2)
    }

    /// Dernière adresse client (`N[-2]`).
    pub fn last_client(&self) -> Ipv4Addr {
        Ipv4Addr::from((self.base | !self.mask) - 1)
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & self.mask == self.base
    }

    /// Filtre de la couche FORWARD : téléphone -> internet (TCP/UDP unicast hors réseau).
    pub fn forward_filter(&self) -> String {
        format!(
            "ip and (tcp or udp) and ip.SrcAddr >= {} and ip.SrcAddr <= {} \
             and (ip.DstAddr < {} or ip.DstAddr > {}) and ip.DstAddr < 224.0.0.0",
            self.first_client(),
            self.last_client(),
            self.network(),
            self.broadcast(),
        )
    }

    /// Filtre de la couche NETWORK : requêtes DNS des appareils vers le PC (`gateway:53`).
    pub fn dns_filter(&self, gateway: Ipv4Addr) -> String {
        format!(
            "inbound and udp and udp.DstPort == 53 and ip.DstAddr == {gateway} \
             and ip.SrcAddr >= {} and ip.SrcAddr <= {}",
            self.first_client(),
            self.last_client(),
        )
    }
}

/// Filtre des réponses du proxy local vers le téléphone.
pub fn out_filter(gateway: Ipv4Addr, tcp_port: u16) -> String {
    format!("outbound and tcp and ip.SrcAddr == {gateway} and tcp.SrcPort == {tcp_port}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net() -> Subnet {
        Subnet::new(Ipv4Addr::new(192, 168, 137, 1), 24).unwrap()
    }

    #[test]
    fn bounds() {
        let n = net();
        assert_eq!(n.network(), Ipv4Addr::new(192, 168, 137, 0));
        assert_eq!(n.broadcast(), Ipv4Addr::new(192, 168, 137, 255));
        assert_eq!(n.first_client(), Ipv4Addr::new(192, 168, 137, 2));
        assert_eq!(n.last_client(), Ipv4Addr::new(192, 168, 137, 254));
    }

    #[test]
    fn membership() {
        let n = net();
        assert!(n.contains(Ipv4Addr::new(192, 168, 137, 77)));
        assert!(!n.contains(Ipv4Addr::new(192, 168, 138, 77)));
        assert!(!n.contains(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn rejects_bad_prefix() {
        assert!(Subnet::new(Ipv4Addr::new(10, 0, 0, 1), 31).is_err());
        assert!(Subnet::new(Ipv4Addr::new(10, 0, 0, 1), 4).is_err());
    }

    #[test]
    fn filters_match_prototype() {
        assert_eq!(
            net().forward_filter(),
            "ip and (tcp or udp) and ip.SrcAddr >= 192.168.137.2 and ip.SrcAddr <= 192.168.137.254 \
             and (ip.DstAddr < 192.168.137.0 or ip.DstAddr > 192.168.137.255) and ip.DstAddr < 224.0.0.0"
        );
        assert_eq!(
            out_filter(Ipv4Addr::new(192, 168, 137, 1), 8229),
            "outbound and tcp and ip.SrcAddr == 192.168.137.1 and tcp.SrcPort == 8229"
        );
    }

    #[test]
    fn dns_filter_targets_gateway_from_clients() {
        assert_eq!(
            net().dns_filter(Ipv4Addr::new(192, 168, 137, 1)),
            "inbound and udp and udp.DstPort == 53 and ip.DstAddr == 192.168.137.1 \
             and ip.SrcAddr >= 192.168.137.2 and ip.SrcAddr <= 192.168.137.254"
        );
        let wide = Subnet::new(Ipv4Addr::new(10, 42, 0, 1), 16).unwrap();
        assert_eq!(
            wide.dns_filter(Ipv4Addr::new(10, 42, 0, 1)),
            "inbound and udp and udp.DstPort == 53 and ip.DstAddr == 10.42.0.1 \
             and ip.SrcAddr >= 10.42.0.2 and ip.SrcAddr <= 10.42.255.254"
        );
    }
}
