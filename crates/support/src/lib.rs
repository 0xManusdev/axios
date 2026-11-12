//! Briques communes aux exécutables de Partage Wi-Fi (application et partage automatique).

pub mod activity;
pub mod logging;
pub mod paths;
pub mod windivert;

use std::net::Ipv4Addr;

/// Port du proxy TCP transparent local.
pub const TCP_PORT: u16 = 8229;
/// Longueur du préfixe du réseau du point d'accès.
pub const PREFIX_LEN: u8 = 24;
/// Verrou système tenu par le processus qui fait tourner le moteur : un seul à la fois.
pub const ENGINE_LOCK: &str = r"Global\PartageWiFi.Moteur";

/// Réseau du point d'accès au format CIDR (ex. `192.168.137.0/24`).
pub fn subnet_cidr(gateway: Ipv4Addr, prefix_len: u8) -> String {
    let mask = u32::MAX
        .checked_shl(32 - u32::from(prefix_len))
        .unwrap_or(0);
    format!("{}/{prefix_len}", Ipv4Addr::from(u32::from(gateway) & mask))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_du_reseau() {
        assert_eq!(
            subnet_cidr(Ipv4Addr::new(192, 168, 137, 1), 24),
            "192.168.137.0/24"
        );
        assert_eq!(subnet_cidr(Ipv4Addr::new(10, 1, 2, 3), 16), "10.1.0.0/16");
        assert_eq!(subnet_cidr(Ipv4Addr::new(10, 1, 2, 3), 0), "0.0.0.0/0");
    }
}
