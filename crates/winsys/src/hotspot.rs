//! Pilotage du point d'accès mobile Windows (WinRT `NetworkOperatorTetheringManager`).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};

use serde::{Deserialize, Serialize};
use windows::Networking::Connectivity::{
    ConnectionProfile, NetworkConnectivityLevel, NetworkInformation,
};
use windows::Networking::NetworkOperators::{
    NetworkOperatorTetheringManager, NetworkOperatorTetheringOperationResult,
    TetheringOperationStatus, TetheringOperationalState, TetheringWiFiBand,
};

use crate::error::{Context, Result, WinsysError};
use crate::mac::normalize_mac;

/// Bande de fréquence du point d'accès.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Band {
    /// Choix automatique par Windows.
    #[serde(rename = "auto")]
    Auto,
    /// 2,4 GHz.
    #[serde(rename = "2.4")]
    Ghz2_4,
    /// 5 GHz.
    #[serde(rename = "5")]
    Ghz5,
    /// 6 GHz.
    #[serde(rename = "6")]
    Ghz6,
}

impl Band {
    fn to_winrt(self) -> TetheringWiFiBand {
        match self {
            Band::Auto => TetheringWiFiBand::Auto,
            Band::Ghz2_4 => TetheringWiFiBand::TwoPointFourGigahertz,
            Band::Ghz5 => TetheringWiFiBand::FiveGigahertz,
            Band::Ghz6 => TetheringWiFiBand::SixGigahertz,
        }
    }

    fn from_winrt(band: TetheringWiFiBand) -> Band {
        match band {
            TetheringWiFiBand::TwoPointFourGigahertz => Band::Ghz2_4,
            TetheringWiFiBand::FiveGigahertz => Band::Ghz5,
            TetheringWiFiBand::SixGigahertz => Band::Ghz6,
            _ => Band::Auto,
        }
    }
}

/// État du point d'accès.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HotspotInfo {
    /// Point d'accès actif.
    pub on: bool,
    /// Nom du réseau.
    pub ssid: String,
    /// Mot de passe.
    pub passphrase: String,
    /// Bande configurée.
    pub band: Band,
    /// Appareils connectés.
    pub client_count: u32,
    /// Maximum d'appareils.
    pub max_clients: u32,
    /// Bandes que la carte Wi-Fi accepte pour le point d'accès (`Auto` toujours en tête).
    pub supported_bands: Vec<Band>,
}

/// Bandes proposées à l'utilisateur, dans l'ordre d'affichage.
pub const ALL_BANDS: [Band; 4] = [Band::Auto, Band::Ghz2_4, Band::Ghz5, Band::Ghz6];

/// Appareil connecté au point d'accès.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HotspotClient {
    /// MAC au format `AA:BB:CC:DD:EE:FF`.
    pub mac: String,
    /// Noms d'hôte connus.
    pub host_names: Vec<String>,
}

/// Longueur maximale d'un SSID, en octets UTF-8.
pub const SSID_MAX_BYTES: usize = 32;
/// Longueur d'un mot de passe WPA2/WPA3 personnel.
pub const PASSPHRASE_LEN: std::ops::RangeInclusive<usize> = 8..=63;

/// Valide SSID (1–32 octets UTF-8) et mot de passe (8–63 caractères ASCII imprimables).
pub fn validate_credentials(ssid: &str, passphrase: &str) -> Result<()> {
    if ssid.is_empty() {
        return Err(WinsysError::InvalidSsid("il ne peut pas être vide"));
    }
    if ssid.len() > SSID_MAX_BYTES {
        return Err(WinsysError::InvalidSsid("32 octets au maximum"));
    }
    if !PASSPHRASE_LEN.contains(&passphrase.len()) {
        return Err(WinsysError::InvalidPassphrase("entre 8 et 63 caractères"));
    }
    if !passphrase.bytes().all(|b| (0x20..=0x7E).contains(&b)) {
        return Err(WinsysError::InvalidPassphrase(
            "caractères ASCII imprimables uniquement",
        ));
    }
    Ok(())
}

/// Nature d'une connexion à internet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceKind {
    /// Wi-Fi.
    Wifi,
    /// Ethernet (et tout ce qui n'est ni Wi-Fi ni réseau mobile, par ex. partage USB).
    Ethernet,
    /// Réseau mobile (WWAN).
    Cellular,
}

/// Connexion à internet pouvant être partagée par le point d'accès.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Source {
    /// Identifiant stable : GUID de l'adaptateur réseau (`NetworkAdapterId`), en texte.
    pub id: String,
    /// Nom du profil (SSID pour le Wi-Fi, « Ethernet »…).
    pub name: String,
    /// Nature de la connexion.
    pub kind: SourceKind,
    /// Bande du Wi-Fi amont si connue (Wi-Fi uniquement).
    pub band: Option<Band>,
}

/// Connexion choisie par [`select_source`] (GUID d'adaptateur) ; `None` = celle par défaut.
static SELECTED: Mutex<Option<String>> = Mutex::new(None);

/// Vrai tant qu'aucun profil internet n'est disponible (journalisation par transition).
static NO_INTERNET: AtomicBool = AtomicBool::new(false);

fn selected() -> MutexGuard<'static, Option<String>> {
    // Une panique ailleurs ne rend pas la valeur incohérente : on la reprend telle quelle.
    SELECTED.lock().unwrap_or_else(|e| e.into_inner())
}

/// Met à jour l'état « pas d'internet » ; renvoie vrai lors d'une transition.
fn record_internet(flag: &AtomicBool, absent: bool) -> bool {
    flag.swap(absent, Ordering::Relaxed) != absent
}

/// Identifiant (GUID texte) de l'adaptateur réseau du profil.
fn adapter_id(profile: &ConnectionProfile) -> Option<String> {
    let guid = profile.NetworkAdapter().ok()?.NetworkAdapterId().ok()?;
    Some(format!("{guid:?}"))
}

fn has_internet(profile: &ConnectionProfile) -> bool {
    profile
        .GetNetworkConnectivityLevel()
        .is_ok_and(|l| l == NetworkConnectivityLevel::InternetAccess)
}

fn source_kind(profile: &ConnectionProfile) -> SourceKind {
    if profile.IsWlanConnectionProfile().unwrap_or(false) {
        SourceKind::Wifi
    } else if profile.IsWwanConnectionProfile().unwrap_or(false) {
        SourceKind::Cellular
    } else {
        SourceKind::Ethernet
    }
}

/// Nom affiché : SSID pour le Wi-Fi, sinon nom du profil, sinon nature de la connexion.
fn source_name(profile: &ConnectionProfile, kind: SourceKind) -> String {
    let ssid = (kind == SourceKind::Wifi)
        .then(|| profile.WlanConnectionProfileDetails().ok())
        .flatten()
        .and_then(|d| d.GetConnectedSsid().ok())
        .map(|s| s.to_string());
    let profile_name = || profile.ProfileName().ok().map(|s| s.to_string());
    [ssid, profile_name()]
        .into_iter()
        .flatten()
        .map(|s| s.trim().to_owned())
        .find(|s| !s.is_empty())
        .unwrap_or_else(|| {
            match kind {
                SourceKind::Wifi => "Wi-Fi",
                SourceKind::Ethernet => "Ethernet",
                SourceKind::Cellular => "Réseau mobile",
            }
            .to_owned()
        })
}

fn to_source(profile: &ConnectionProfile) -> Option<Source> {
    let id = adapter_id(profile)?;
    let kind = source_kind(profile);
    let band = match kind {
        SourceKind::Wifi => crate::wlan::wifi_band(&id),
        _ => None,
    };
    Some(Source {
        name: source_name(profile, kind),
        id,
        kind,
        band,
    })
}

/// Profils connectés à internet (niveau `InternetAccess`).
fn internet_profiles() -> Result<Vec<ConnectionProfile>> {
    crate::com::ensure();
    let profiles =
        NetworkInformation::GetConnectionProfiles().ctx("Lecture des connexions réseau")?;
    Ok(profiles.into_iter().filter(has_internet).collect())
}

/// Profil connecté à internet de l'adaptateur `id`.
fn find_profile(id: &str) -> Option<ConnectionProfile> {
    match internet_profiles() {
        Ok(list) => list
            .into_iter()
            .find(|p| adapter_id(p).is_some_and(|a| a.eq_ignore_ascii_case(id))),
        Err(e) => {
            log::debug!("{e}");
            None
        }
    }
}

/// Profil partagé : la connexion choisie si elle est disponible, sinon celle d'internet par défaut.
fn current_profile() -> Result<ConnectionProfile> {
    crate::com::ensure();
    let choice = selected().clone();
    let chosen = choice.as_deref().and_then(|id| {
        let found = find_profile(id);
        if found.is_none() {
            log::debug!("connexion choisie {id} indisponible : connexion par défaut utilisée");
        }
        found
    });
    let profile = match chosen {
        Some(p) => Ok(p),
        None => NetworkInformation::GetInternetConnectionProfile(),
    };
    match profile {
        Ok(p) => {
            if record_internet(&NO_INTERNET, false) {
                log::info!("connexion internet retrouvée");
            }
            Ok(p)
        }
        Err(e) => {
            if record_internet(&NO_INTERNET, true) {
                log::warn!("pas de profil de connexion internet : {e}");
            } else {
                log::debug!("pas de profil de connexion internet : {e}");
            }
            Err(WinsysError::NoInternet)
        }
    }
}

fn manager_for(profile: &ConnectionProfile) -> Result<NetworkOperatorTetheringManager> {
    NetworkOperatorTetheringManager::CreateFromConnectionProfile(profile)
        .ctx("Création du gestionnaire de point d'accès")
}

fn manager() -> Result<NetworkOperatorTetheringManager> {
    manager_for(&current_profile()?)
}

/// Dédoublonne par identifiant et place la connexion par défaut en tête (ordre sinon conservé).
fn order_sources(list: Vec<Source>, default_id: Option<&str>) -> Vec<Source> {
    let mut out: Vec<Source> = Vec::with_capacity(list.len());
    for s in list {
        if !out.iter().any(|o| o.id.eq_ignore_ascii_case(&s.id)) {
            out.push(s);
        }
    }
    if let Some(pos) =
        default_id.and_then(|d| out.iter().position(|s| s.id.eq_ignore_ascii_case(d)))
    {
        let first = out.remove(pos);
        out.insert(0, first);
    }
    out
}

/// Connexions ayant accès à internet (niveau `InternetAccess`), celle par défaut en premier.
pub fn sources() -> Result<Vec<Source>> {
    let profiles = internet_profiles()?;
    let default_id = NetworkInformation::GetInternetConnectionProfile()
        .ok()
        .and_then(|p| adapter_id(&p));
    let list = profiles.iter().filter_map(to_source).collect();
    Ok(order_sources(list, default_id.as_deref()))
}

/// Connexion utilisée par le point d'accès : celle choisie si elle est disponible, sinon
/// celle d'internet par défaut. `None` s'il n'y en a aucune.
pub fn current_source() -> Result<Option<Source>> {
    match current_profile() {
        Ok(p) => Ok(to_source(&p)),
        Err(WinsysError::NoInternet) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Choisit la connexion à partager (`None` = celle d'internet par défaut). Mémorisé dans le
/// processus ; toutes les fonctions du module (`info`, `start`, `configure`…) l'utilisent.
/// Si le point d'accès est actif, il est redémarré sur la nouvelle connexion.
pub fn select_source(id: Option<&str>) -> Result<HotspotInfo> {
    let choice = id
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let before = current_profile().ok();
    let previous = std::mem::replace(&mut *selected(), choice.clone());
    log::info!(
        "connexion partagée choisie : {}",
        choice.as_deref().unwrap_or("connexion par défaut")
    );
    let after = current_profile()?;
    let new_mgr = manager_for(&after)?;

    let old_mgr = match before {
        Some(old) if adapter_id(&old) != adapter_id(&after) => manager_for(&old)?,
        // Même connexion effective (ou aucune avant) : rien à redémarrer.
        _ => return read_info(&new_mgr),
    };
    let was_on = old_mgr
        .TetheringOperationalState()
        .ctx("Lecture de l'état")?
        == TetheringOperationalState::On;
    if !was_on {
        return read_info(&new_mgr);
    }

    log::info!("changement de connexion partagée : redémarrage du point d'accès");
    if let Err(e) = stop_with(&old_mgr) {
        *selected() = previous;
        return Err(e);
    }
    if let Err(e) = start_with(&new_mgr) {
        // On rend le point d'accès sur l'ancienne connexion, avec l'ancien choix.
        *selected() = previous;
        if let Err(restart) = start_with(&old_mgr) {
            log::warn!("redémarrage sur l'ancienne connexion impossible : {restart}");
        }
        return Err(e);
    }
    read_info(&new_mgr)
}

fn check_result(result: &NetworkOperatorTetheringOperationResult) -> Result<()> {
    let status = result.Status().ctx("Lecture du résultat de l'opération")?;
    if status == TetheringOperationStatus::Success {
        return Ok(());
    }
    let detail = result
        .AdditionalErrorMessage()
        .map(|m| m.to_string())
        .unwrap_or_default();
    let message = format!("{} {detail}", status_label(status));
    Err(WinsysError::Tethering(message.trim().to_owned()))
}

fn status_label(status: TetheringOperationStatus) -> String {
    match status {
        TetheringOperationStatus::Unknown => "échec inconnu".into(),
        TetheringOperationStatus::MobileBroadbandDeviceOff => "carte réseau mobile éteinte".into(),
        TetheringOperationStatus::WiFiDeviceOff => "Wi-Fi désactivé".into(),
        TetheringOperationStatus::EntitlementCheckTimeout => "délai de vérification dépassé".into(),
        TetheringOperationStatus::EntitlementCheckFailure => "partage non autorisé".into(),
        TetheringOperationStatus::OperationInProgress => "opération déjà en cours".into(),
        TetheringOperationStatus::BluetoothDeviceOff => "Bluetooth désactivé".into(),
        TetheringOperationStatus::NetworkLimitedConnectivity => "connectivité limitée".into(),
        other => format!("état {}", other.0),
    }
}

fn read_info(mgr: &NetworkOperatorTetheringManager) -> Result<HotspotInfo> {
    let cfg = mgr
        .GetCurrentAccessPointConfiguration()
        .ctx("Lecture de la configuration du point d'accès")?;
    let state = mgr
        .TetheringOperationalState()
        .ctx("Lecture de l'état du point d'accès")?;
    Ok(HotspotInfo {
        on: state == TetheringOperationalState::On,
        ssid: cfg.Ssid().map(|s| s.to_string()).unwrap_or_default(),
        passphrase: cfg.Passphrase().map(|s| s.to_string()).unwrap_or_default(),
        band: cfg.Band().map(Band::from_winrt).unwrap_or(Band::Auto),
        client_count: mgr.ClientCount().unwrap_or(0),
        max_clients: mgr.MaxClientCount().unwrap_or(0),
        supported_bands: ALL_BANDS
            .into_iter()
            .filter(|&b| b == Band::Auto || cfg.IsBandSupported(b.to_winrt()).unwrap_or(false))
            .collect(),
    })
}

fn start_with(mgr: &NetworkOperatorTetheringManager) -> Result<()> {
    let state = mgr.TetheringOperationalState().ctx("Lecture de l'état")?;
    if state == TetheringOperationalState::On {
        return Ok(());
    }
    log::info!("démarrage du point d'accès");
    let result = mgr
        .StartTetheringAsync()
        .and_then(|op| op.join())
        .ctx("Démarrage du point d'accès")?;
    check_result(&result)
}

fn stop_with(mgr: &NetworkOperatorTetheringManager) -> Result<()> {
    let state = mgr.TetheringOperationalState().ctx("Lecture de l'état")?;
    if state == TetheringOperationalState::Off {
        return Ok(());
    }
    log::info!("arrêt du point d'accès");
    let result = mgr
        .StopTetheringAsync()
        .and_then(|op| op.join())
        .ctx("Arrêt du point d'accès")?;
    check_result(&result)
}

/// État courant du point d'accès.
pub fn info() -> Result<HotspotInfo> {
    read_info(&manager()?)
}

/// Démarre le point d'accès (sans effet s'il est déjà actif).
pub fn start() -> Result<HotspotInfo> {
    let mgr = manager()?;
    start_with(&mgr)?;
    read_info(&mgr)
}

/// Arrête le point d'accès (sans effet s'il est déjà éteint).
pub fn stop() -> Result<HotspotInfo> {
    let mgr = manager()?;
    stop_with(&mgr)?;
    read_info(&mgr)
}

/// Valide (SSID 1–32 octets UTF-8, mot de passe 8–63 ASCII imprimables) puis applique.
/// Si le point d'accès est actif, l'arrête, configure et le redémarre.
pub fn configure(ssid: &str, passphrase: &str, band: Option<Band>) -> Result<HotspotInfo> {
    validate_credentials(ssid, passphrase)?;
    let mgr = manager()?;
    let cfg = mgr
        .GetCurrentAccessPointConfiguration()
        .ctx("Lecture de la configuration du point d'accès")?;
    if let Some(band) = band {
        let supported = cfg
            .IsBandSupported(band.to_winrt())
            .ctx("Vérification de la bande Wi-Fi")?;
        if !supported {
            return Err(WinsysError::UnsupportedBand);
        }
        cfg.SetBand(band.to_winrt())
            .ctx("Choix de la bande Wi-Fi")?;
    }
    cfg.SetSsid(&ssid.into()).ctx("Choix du nom du réseau")?;
    cfg.SetPassphrase(&passphrase.into())
        .ctx("Choix du mot de passe")?;

    let was_on =
        mgr.TetheringOperationalState().ctx("Lecture de l'état")? == TetheringOperationalState::On;
    if was_on {
        stop_with(&mgr)?;
    }
    log::info!("application de la configuration du point d'accès");
    let applied = mgr
        .ConfigureAccessPointAsync(&cfg)
        .and_then(|op| op.join())
        .ctx("Configuration du point d'accès");
    // Redémarrage même si la configuration a échoué : on rend le point d'accès dans son état initial.
    if was_on {
        if let Err(e) = start_with(&mgr) {
            if applied.is_ok() {
                return Err(e);
            }
            log::warn!("redémarrage après échec de configuration impossible : {e}");
        }
    }
    applied?;
    read_info(&mgr)
}

/// Appareils actuellement connectés au point d'accès.
pub fn clients() -> Result<Vec<HotspotClient>> {
    let mgr = manager()?;
    let list = mgr
        .GetTetheringClients()
        .ctx("Lecture des appareils connectés")?;
    let mut out = Vec::new();
    for client in list {
        let mac = client
            .MacAddress()
            .map(|m| normalize_mac(&m.to_string()))
            .unwrap_or_default();
        let host_names = client
            .HostNames()
            .map(|names| {
                names
                    .into_iter()
                    .filter_map(|h| h.DisplayName().ok())
                    .map(|n| n.to_string())
                    .filter(|n| !n.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        out.push(HotspotClient { mac, host_names });
    }
    Ok(out)
}

/// Empêche Windows de couper le point d'accès quand aucun appareil n'est connecté. Best effort.
pub fn set_keep_alive(enabled: bool) -> Result<()> {
    crate::com::ensure();
    if enabled {
        NetworkOperatorTetheringManager::DisableNoConnectionsTimeout()
            .ctx("Désactivation du délai d'inactivité du point d'accès")
    } else {
        NetworkOperatorTetheringManager::EnableNoConnectionsTimeout()
            .ctx("Réactivation du délai d'inactivité du point d'accès")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn band_serde_exact() {
        for (band, text) in [
            (Band::Auto, "\"auto\""),
            (Band::Ghz2_4, "\"2.4\""),
            (Band::Ghz5, "\"5\""),
            (Band::Ghz6, "\"6\""),
        ] {
            assert_eq!(serde_json::to_string(&band).unwrap(), text);
            assert_eq!(serde_json::from_str::<Band>(text).unwrap(), band);
        }
        assert!(serde_json::from_str::<Band>("\"7\"").is_err());
    }

    #[test]
    fn info_is_camel_case() {
        let info = HotspotInfo {
            on: true,
            ssid: "x".into(),
            passphrase: "y".into(),
            band: Band::Ghz5,
            client_count: 1,
            max_clients: 8,
            supported_bands: vec![Band::Auto, Band::Ghz2_4, Band::Ghz5],
        };
        let v = serde_json::to_value(&info).unwrap();
        assert_eq!(v["clientCount"], 1);
        assert_eq!(v["maxClients"], 8);
        assert_eq!(v["band"], "5");
        assert_eq!(v["supportedBands"], serde_json::json!(["auto", "2.4", "5"]));
    }

    #[test]
    fn ssid_validation() {
        assert!(validate_credentials("Réseau", "motdepasse").is_ok());
        assert!(validate_credentials("a", "motdepasse").is_ok());
        assert!(matches!(
            validate_credentials("", "motdepasse"),
            Err(WinsysError::InvalidSsid(_))
        ));
        assert!(validate_credentials(&"a".repeat(32), "motdepasse").is_ok());
        assert!(matches!(
            validate_credentials(&"a".repeat(33), "motdepasse"),
            Err(WinsysError::InvalidSsid(_))
        ));
        // 16 x "é" = 32 octets (accepté) ; 17 = 34 octets (refusé).
        assert!(validate_credentials(&"é".repeat(16), "motdepasse").is_ok());
        assert!(validate_credentials(&"é".repeat(17), "motdepasse").is_err());
    }

    #[test]
    fn passphrase_validation() {
        assert!(validate_credentials("s", "1234567").is_err());
        assert!(validate_credentials("s", "12345678").is_ok());
        assert!(validate_credentials("s", &"a".repeat(63)).is_ok());
        assert!(validate_credentials("s", &"a".repeat(64)).is_err());
        assert!(validate_credentials("s", "avec espace ok!~").is_ok());
        assert!(matches!(
            validate_credentials("s", "motdepassé"),
            Err(WinsysError::InvalidPassphrase(_))
        ));
        assert!(validate_credentials("s", "tab\tulation").is_err());
        assert!(validate_credentials("s", "del\u{7f}del123").is_err());
    }

    #[test]
    fn configure_rejects_before_touching_system() {
        assert!(matches!(
            configure("", "motdepasse", None),
            Err(WinsysError::InvalidSsid(_))
        ));
        assert!(matches!(
            configure("ok", "court", Some(Band::Auto)),
            Err(WinsysError::InvalidPassphrase(_))
        ));
    }

    #[test]
    fn error_messages_are_french_and_short() {
        assert_eq!(
            WinsysError::NoInternet.to_string(),
            "Aucune connexion internet"
        );
    }

    fn source(id: &str, kind: SourceKind) -> Source {
        Source {
            id: id.into(),
            name: id.into(),
            kind,
            band: None,
        }
    }

    #[test]
    fn source_kind_serde() {
        for (kind, text) in [
            (SourceKind::Wifi, "\"wifi\""),
            (SourceKind::Ethernet, "\"ethernet\""),
            (SourceKind::Cellular, "\"cellular\""),
        ] {
            assert_eq!(serde_json::to_string(&kind).unwrap(), text);
            assert_eq!(serde_json::from_str::<SourceKind>(text).unwrap(), kind);
        }
    }

    #[test]
    fn source_is_camel_case() {
        let s = Source {
            id: "4D36E972-E325-11CE-BFC1-08002BE10318".into(),
            name: "Box".into(),
            kind: SourceKind::Wifi,
            band: Some(Band::Ghz5),
        };
        assert_eq!(
            serde_json::to_value(&s).unwrap(),
            serde_json::json!({
                "id": "4D36E972-E325-11CE-BFC1-08002BE10318",
                "name": "Box",
                "kind": "wifi",
                "band": "5",
            })
        );
        let wired = Source {
            band: None,
            ..source("A", SourceKind::Ethernet)
        };
        assert_eq!(
            serde_json::to_value(&wired).unwrap()["band"],
            serde_json::Value::Null
        );
    }

    #[test]
    fn sources_default_first_and_deduplicated() {
        let list = vec![
            source("A", SourceKind::Ethernet),
            source("B", SourceKind::Wifi),
            source("C", SourceKind::Cellular),
            source("b", SourceKind::Wifi),
        ];
        let ids = |v: Vec<Source>| v.into_iter().map(|s| s.id).collect::<Vec<_>>();
        assert_eq!(ids(order_sources(list.clone(), Some("b"))), ["B", "A", "C"]);
        assert_eq!(ids(order_sources(list.clone(), Some("C"))), ["C", "A", "B"]);
        assert_eq!(ids(order_sources(list.clone(), None)), ["A", "B", "C"]);
        assert_eq!(ids(order_sources(list, Some("Z"))), ["A", "B", "C"]);
        assert!(order_sources(Vec::new(), Some("A")).is_empty());
    }

    #[test]
    fn no_internet_logged_once_per_transition() {
        let flag = AtomicBool::new(false);
        assert!(!record_internet(&flag, false)); // présent -> présent
        assert!(record_internet(&flag, true)); // présent -> absent : journalisé
        assert!(!record_internet(&flag, true)); // absent -> absent : debug
        assert!(!record_internet(&flag, true));
        assert!(record_internet(&flag, false)); // retour
        assert!(record_internet(&flag, true)); // nouvelle perte : journalisée à nouveau
    }

    #[test]
    fn read_only_sources_work() {
        // Lecture seule : affiche les connexions de cette machine (`cargo test -- --nocapture`).
        let list = sources().unwrap();
        for s in &list {
            assert!(!s.id.is_empty() && !s.name.is_empty());
            if s.kind != SourceKind::Wifi {
                assert_eq!(s.band, None);
            }
            println!(
                "source : {s:?} ; wifi_band = {:?}",
                crate::net::wifi_band(&s.id)
            );
        }
        println!("connexion partagée : {:?}", current_source().unwrap());
    }

    #[test]
    #[ignore = "modifie le point d'accès réel (admin requis)"]
    fn start_stop_roundtrip() {
        start().unwrap();
        stop().unwrap();
    }
}
