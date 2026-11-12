//! Informations réseau : passerelle ICS, interface du point d'accès, voisins ARP, bande du
//! Wi-Fi amont.

use std::net::Ipv4Addr;

use windows::core::w;
use windows::Win32::Foundation::{ERROR_SUCCESS, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetIpNetTable2, GetUnicastIpAddressTable, MIB_IPNET_TABLE2,
    MIB_UNICASTIPADDRESS_TABLE,
};
use windows::Win32::Networking::WinSock::{
    NlnsDelay, NlnsPermanent, NlnsProbe, NlnsReachable, NlnsStale, AF_INET, NL_NEIGHBOR_STATE,
};
use windows::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ};

use crate::mac::format_mac;

pub use crate::wlan::wifi_band;

/// Adresse ICS par défaut de Windows.
pub const DEFAULT_ICS_GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 168, 137, 1);

/// IP du PC côté point d'accès (clé `ScopeAddress` d'ICS, 192.168.137.1 par défaut).
pub fn ics_gateway() -> Ipv4Addr {
    read_scope_address()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(DEFAULT_ICS_GATEWAY)
}

fn read_scope_address() -> Option<String> {
    let mut buf = [0u16; 64];
    let mut size = std::mem::size_of_val(&buf) as u32;
    // SAFETY: `buf` et `size` (en octets) décrivent le même tampon, valide pendant l'appel.
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            w!(r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters"),
            w!("ScopeAddress"),
            RRF_RT_REG_SZ,
            None,
            Some(buf.as_mut_ptr().cast()),
            Some(&mut size),
        )
    };
    if rc != ERROR_SUCCESS {
        return None;
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16(&buf[..len]).ok()
}

/// Table MIB libérée automatiquement.
struct MibTable<T>(*mut T);

impl<T> Drop for MibTable<T> {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: le pointeur provient d'une fonction IP Helper qui impose `FreeMibTable`.
            unsafe { FreeMibTable(self.0.cast()) };
        }
    }
}

fn ipv4_from_sockaddr(raw_be: u32) -> Ipv4Addr {
    // `S_addr` est stocké en ordre réseau : ses octets en mémoire sont l'adresse.
    Ipv4Addr::from(raw_be.to_ne_bytes())
}

/// Index de l'interface qui porte l'IPv4 `ip`.
pub fn interface_index_for(ip: Ipv4Addr) -> Option<u32> {
    let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
    // SAFETY: `table` reçoit une table allouée par Windows, libérée par `MibTable`.
    let rc = unsafe { GetUnicastIpAddressTable(AF_INET, &mut table) };
    let guard = MibTable(table);
    if rc != NO_ERROR || guard.0.is_null() {
        log::warn!("GetUnicastIpAddressTable a échoué ({})", rc.0);
        return None;
    }
    // SAFETY: la table contient `NumEntries` lignes contiguës, valides tant que `guard` vit.
    let rows = unsafe {
        let t = &*guard.0;
        std::slice::from_raw_parts(t.Table.as_ptr(), t.NumEntries as usize)
    };
    rows.iter()
        .find(|r| {
            // SAFETY: famille AF_INET demandée : le membre `Ipv4` est celui initialisé.
            let raw = unsafe { r.Address.Ipv4.sin_addr.S_un.S_addr };
            ipv4_from_sockaddr(raw) == ip
        })
        .map(|r| r.InterfaceIndex)
}

fn neighbor_is_resolved(state: NL_NEIGHBOR_STATE) -> bool {
    [
        NlnsReachable,
        NlnsStale,
        NlnsDelay,
        NlnsProbe,
        NlnsPermanent,
    ]
    .contains(&state)
}

/// Voisins ARP résolus sur l'interface `if_index` : `(ip, "AA:BB:CC:DD:EE:FF")`.
pub fn neighbors(if_index: u32) -> Vec<(Ipv4Addr, String)> {
    let mut table: *mut MIB_IPNET_TABLE2 = std::ptr::null_mut();
    // SAFETY: `table` reçoit une table allouée par Windows, libérée par `MibTable`.
    let rc = unsafe { GetIpNetTable2(AF_INET, &mut table) };
    let guard = MibTable(table);
    if rc != NO_ERROR || guard.0.is_null() {
        log::warn!("GetIpNetTable2 a échoué ({})", rc.0);
        return Vec::new();
    }
    // SAFETY: voir `interface_index_for`.
    let rows = unsafe {
        let t = &*guard.0;
        std::slice::from_raw_parts(t.Table.as_ptr(), t.NumEntries as usize)
    };
    rows.iter()
        .filter(|r| {
            r.InterfaceIndex == if_index
                && r.PhysicalAddressLength == 6
                && neighbor_is_resolved(r.State)
        })
        .map(|r| {
            // SAFETY: famille AF_INET demandée : le membre `Ipv4` est initialisé.
            let raw = unsafe { r.Address.Ipv4.sin_addr.S_un.S_addr };
            (ipv4_from_sockaddr(raw), format_mac(&r.PhysicalAddress[..6]))
        })
        .filter(|(ip, mac)| !ip.is_multicast() && mac != "FF:FF:FF:FF:FF:FF")
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sockaddr_conversion() {
        // 192.168.137.1 en mémoire : C0 A8 89 01.
        let raw = u32::from_ne_bytes([192, 168, 137, 1]);
        assert_eq!(ipv4_from_sockaddr(raw), Ipv4Addr::new(192, 168, 137, 1));
    }

    #[test]
    fn read_only_calls_work() {
        let _ = ics_gateway();
        assert!(interface_index_for(Ipv4Addr::new(127, 0, 0, 1)).is_some());
        let _ = neighbors(1);
    }
}
