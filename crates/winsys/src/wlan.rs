//! Wi-Fi amont via WlanAPI : bande de la connexion d'un adaptateur.

use std::ffi::c_void;

use windows::core::GUID;
use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
use windows::Win32::NetworkManagement::WiFi::{
    dot11_BSS_type_any, wlan_interface_state_connected, wlan_intf_opcode_channel_number,
    wlan_intf_opcode_current_connection, WlanCloseHandle, WlanEnumInterfaces, WlanFreeMemory,
    WlanGetNetworkBssList, WlanOpenHandle, WlanQueryInterface, WLAN_API_VERSION_2_0,
    WLAN_BSS_ENTRY, WLAN_BSS_LIST, WLAN_CONNECTION_ATTRIBUTES, WLAN_INTERFACE_INFO,
    WLAN_INTERFACE_INFO_LIST, WLAN_INTF_OPCODE,
};

use crate::hotspot::Band;

/// Bande d'un canal Wi-Fi : 1–14 → 2,4 GHz ; 32–177 → 5 GHz ; sinon inconnue.
///
/// Les canaux 6 GHz réutilisent les numéros 1–233 : seul le numéro ne permet pas de les
/// reconnaître (voir [`band_for_frequency`]).
fn band_for_channel(channel: u32) -> Option<Band> {
    match channel {
        1..=14 => Some(Band::Ghz2_4),
        32..=177 => Some(Band::Ghz5),
        _ => None,
    }
}

/// Bande d'une fréquence centrale en MHz : 2,4 GHz (2401–2495), 5 GHz (5150–5924),
/// 6 GHz (5925–7125) ; sinon inconnue.
fn band_for_frequency(mhz: u32) -> Option<Band> {
    match mhz {
        2401..=2495 => Some(Band::Ghz2_4),
        5150..=5924 => Some(Band::Ghz5),
        5925..=7125 => Some(Band::Ghz6),
        _ => None,
    }
}

/// GUID texte (`XXXXXXXX-XXXX-…`, accolades et casse indifférentes).
fn parse_guid(text: &str) -> Option<GUID> {
    let t = text.trim();
    let t = t
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or(t);
    GUID::try_from(t).ok()
}

/// Session WlanAPI fermée automatiquement.
struct Session(HANDLE);

impl Session {
    fn open() -> Option<Session> {
        let mut version = 0u32;
        let mut handle = HANDLE::default();
        // SAFETY: les deux pointeurs de sortie sont valides pendant l'appel.
        let rc = unsafe { WlanOpenHandle(WLAN_API_VERSION_2_0, None, &mut version, &mut handle) };
        if rc != ERROR_SUCCESS.0 {
            log::debug!("WlanOpenHandle a échoué ({rc})");
            return None;
        }
        Some(Session(handle))
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: handle obtenu par un `WlanOpenHandle` réussi, fermé une seule fois.
        unsafe { WlanCloseHandle(self.0, None) };
    }
}

/// Mémoire allouée par WlanAPI, libérée automatiquement par `WlanFreeMemory`.
struct WlanMem<T>(*mut T);

impl<T> WlanMem<T> {
    fn null() -> WlanMem<T> {
        WlanMem(std::ptr::null_mut())
    }
}

impl<T> Drop for WlanMem<T> {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: le pointeur provient d'une fonction WlanAPI qui impose `WlanFreeMemory`.
            unsafe { WlanFreeMemory(self.0.cast::<c_void>().cast_const()) };
        }
    }
}

/// Interfaces Wi-Fi présentes.
fn interfaces(session: &Session) -> Vec<GUID> {
    let mut list = WlanMem::<WLAN_INTERFACE_INFO_LIST>::null();
    // SAFETY: `list.0` reçoit une liste allouée par WlanAPI, libérée par `WlanMem`.
    let rc = unsafe { WlanEnumInterfaces(session.0, None, &mut list.0) };
    if rc != ERROR_SUCCESS.0 || list.0.is_null() {
        log::debug!("WlanEnumInterfaces a échoué ({rc})");
        return Vec::new();
    }
    // SAFETY: la liste contient `dwNumberOfItems` éléments contigus à partir de `InterfaceInfo`,
    // valides tant que `list` vit.
    let items: &[WLAN_INTERFACE_INFO] = unsafe {
        let l = list.0;
        std::slice::from_raw_parts(
            std::ptr::addr_of!((*l).InterfaceInfo).cast::<WLAN_INTERFACE_INFO>(),
            (*l).dwNumberOfItems as usize,
        )
    };
    items.iter().map(|i| i.InterfaceGuid).collect()
}

/// Lit une valeur `T` de l'interface `guid` (`WlanQueryInterface`).
fn query<T: Copy>(session: &Session, guid: &GUID, opcode: WLAN_INTF_OPCODE) -> Option<T> {
    let mut size = 0u32;
    let mut data = WlanMem::<c_void>::null();
    // SAFETY: `size` et `data.0` sont des sorties valides ; `data` libère la mémoire renvoyée.
    let rc =
        unsafe { WlanQueryInterface(session.0, guid, opcode, None, &mut size, &mut data.0, None) };
    if rc != ERROR_SUCCESS.0 || data.0.is_null() || (size as usize) < std::mem::size_of::<T>() {
        log::debug!("WlanQueryInterface({}) a échoué ({rc})", opcode.0);
        return None;
    }
    // SAFETY: WlanAPI a renvoyé au moins `size_of::<T>()` octets pour cet opcode ; lecture
    // non alignée par prudence, copiée avant la libération.
    Some(unsafe { data.0.cast::<T>().read_unaligned() })
}

/// Fréquence (MHz) du point d'accès auquel l'interface est connectée, d'après la liste BSS.
fn connected_frequency(session: &Session, guid: &GUID) -> Option<u32> {
    let conn: WLAN_CONNECTION_ATTRIBUTES =
        query(session, guid, wlan_intf_opcode_current_connection)?;
    if conn.isState != wlan_interface_state_connected {
        return None;
    }
    let bssid = conn.wlanAssociationAttributes.dot11Bssid;
    let mut list = WlanMem::<WLAN_BSS_LIST>::null();
    // SAFETY: sans SSID, le type et la sécurité sont ignorés ; `list.0` reçoit une liste
    // allouée par WlanAPI, libérée par `WlanMem`.
    let rc = unsafe {
        WlanGetNetworkBssList(
            session.0,
            guid,
            None,
            dot11_BSS_type_any,
            false,
            None,
            &mut list.0,
        )
    };
    if rc != ERROR_SUCCESS.0 || list.0.is_null() {
        log::debug!("WlanGetNetworkBssList a échoué ({rc})");
        return None;
    }
    // SAFETY: la liste contient `dwNumberOfItems` entrées contiguës à partir de
    // `wlanBssEntries`, valides tant que `list` vit.
    let entries: &[WLAN_BSS_ENTRY] = unsafe {
        let l = list.0;
        std::slice::from_raw_parts(
            std::ptr::addr_of!((*l).wlanBssEntries).cast::<WLAN_BSS_ENTRY>(),
            (*l).dwNumberOfItems as usize,
        )
    };
    entries
        .iter()
        .find(|e| e.dot11Bssid == bssid)
        .map(|e| e.ulChCenterFrequency / 1000) // kHz -> MHz
}

/// Bande de la connexion Wi-Fi de l'adaptateur `adapter_id` (GUID texte), via WlanAPI.
///
/// Fréquence du point d'accès connecté (liste BSS, reconnaît le 6 GHz) ; à défaut numéro de
/// canal (`wlan_intf_opcode_channel_number`) : 1–14 → 2,4 GHz, 32–177 → 5 GHz.
/// `None` si l'adaptateur n'est pas une interface Wi-Fi connectée ou en cas d'échec.
pub fn wifi_band(adapter_id: &str) -> Option<Band> {
    let guid = parse_guid(adapter_id)?;
    let session = Session::open()?;
    if !interfaces(&session).contains(&guid) {
        return None;
    }
    connected_frequency(&session, &guid)
        .and_then(band_for_frequency)
        .or_else(|| {
            query::<u32>(&session, &guid, wlan_intf_opcode_channel_number)
                .and_then(band_for_channel)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_to_band() {
        for ch in [1, 6, 11, 13, 14] {
            assert_eq!(band_for_channel(ch), Some(Band::Ghz2_4), "{ch}");
        }
        for ch in [32, 36, 48, 100, 144, 149, 165, 177] {
            assert_eq!(band_for_channel(ch), Some(Band::Ghz5), "{ch}");
        }
        for ch in [0, 15, 31, 178, 233, u32::MAX] {
            assert_eq!(band_for_channel(ch), None, "{ch}");
        }
    }

    #[test]
    fn frequency_to_band() {
        assert_eq!(band_for_frequency(2412), Some(Band::Ghz2_4)); // canal 1
        assert_eq!(band_for_frequency(2484), Some(Band::Ghz2_4)); // canal 14
        assert_eq!(band_for_frequency(5180), Some(Band::Ghz5)); // canal 36
        assert_eq!(band_for_frequency(5885), Some(Band::Ghz5)); // canal 177
        assert_eq!(band_for_frequency(5935), Some(Band::Ghz6)); // canal 6 GHz n° 2
        assert_eq!(band_for_frequency(5955), Some(Band::Ghz6)); // canal 6 GHz n° 1
        assert_eq!(band_for_frequency(7115), Some(Band::Ghz6)); // canal 6 GHz n° 233
        for mhz in [0, 2400, 3000, 5000, 7200, 60_000] {
            assert_eq!(band_for_frequency(mhz), None, "{mhz}");
        }
    }

    #[test]
    fn guid_text() {
        let g = parse_guid("4d36e972-e325-11ce-bfc1-08002be10318").unwrap();
        assert_eq!(format!("{g:?}"), "4D36E972-E325-11CE-BFC1-08002BE10318");
        assert_eq!(
            parse_guid("{4D36E972-E325-11CE-BFC1-08002BE10318}"),
            Some(g)
        );
        assert_eq!(
            parse_guid(" 4D36E972-E325-11CE-BFC1-08002BE10318 "),
            Some(g)
        );
        assert_eq!(parse_guid(""), None);
        assert_eq!(parse_guid("pas un guid"), None);
    }

    #[test]
    fn read_only_interfaces() {
        // Lecture seule : affiche fréquence et canal des interfaces Wi-Fi (`--nocapture`).
        let Some(session) = Session::open() else {
            return; // pas de service WLAN sur cette machine
        };
        for guid in interfaces(&session) {
            let mhz = connected_frequency(&session, &guid);
            let channel = query::<u32>(&session, &guid, wlan_intf_opcode_channel_number);
            println!("interface {guid:?} : {mhz:?} MHz, canal {channel:?}");
            if let (Some(mhz), Some(ch)) = (mhz, channel) {
                // Hors 6 GHz, fréquence et canal doivent désigner la même bande.
                if band_for_frequency(mhz) != Some(Band::Ghz6) {
                    assert_eq!(band_for_frequency(mhz), band_for_channel(ch));
                }
            }
        }
    }

    #[test]
    fn unknown_adapter_has_no_band() {
        assert_eq!(wifi_band("pas un guid"), None);
        assert_eq!(wifi_band("00000000-0000-0000-0000-000000000000"), None);
    }
}
