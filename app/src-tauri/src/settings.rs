//! Réglages de l'application (`settings.json`) et fusion des modifications partielles.

use std::net::Ipv4Addr;

use serde::{Deserialize, Deserializer, Serialize};

use crate::store::lenient;

/// Résolveur DNS imposé aux appareils.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Dns {
    /// DNS de Windows (aucune redirection).
    #[default]
    Auto,
    Cloudflare,
    Google,
    /// Adresse IPv4 de `customDns`.
    Custom,
}

/// Réglages exposés à l'interface (forme `Settings` de `types.ts`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    #[serde(deserialize_with = "lenient")]
    pub autostart: bool,
    #[serde(deserialize_with = "lenient")]
    pub share_on_launch: bool,
    #[serde(deserialize_with = "lenient")]
    pub notifications: bool,
    #[serde(deserialize_with = "lenient")]
    pub ad_block: bool,
    #[serde(deserialize_with = "lenient")]
    pub isolate: bool,
    /// Débit maximal par défaut (Mb/s), `None` = illimité.
    #[serde(deserialize_with = "lenient")]
    pub default_limit: Option<f64>,
    #[serde(deserialize_with = "lenient")]
    pub dns: Dns,
    #[serde(deserialize_with = "lenient")]
    pub custom_dns: String,
    #[serde(deserialize_with = "lenient_true")]
    pub keep_alive: bool,
    #[serde(deserialize_with = "lenient")]
    pub auto_restart: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            autostart: false,
            share_on_launch: false,
            notifications: false,
            ad_block: false,
            isolate: false,
            default_limit: None,
            dns: Dns::Auto,
            custom_dns: String::new(),
            keep_alive: true,
            auto_restart: false,
        }
    }
}

fn lenient_true<'de, D: Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    let value = serde_json::Value::deserialize(deserializer)?;
    Ok(value.as_bool().unwrap_or(true))
}

/// Contenu de `settings.json` : les réglages et l'état interne non exposé.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SettingsFile {
    #[serde(flatten)]
    pub settings: Settings,
    /// Connexion partagée choisie (GUID d'adaptateur) ; `None` = celle par défaut.
    #[serde(deserialize_with = "lenient", skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
}

/// `Some(v)` pour un champ présent, y compris `null` (→ `Some(None)`).
fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// Modification partielle envoyée par l'interface (`Partial<Settings>`).
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SettingsPatch {
    pub autostart: Option<bool>,
    pub share_on_launch: Option<bool>,
    pub notifications: Option<bool>,
    pub ad_block: Option<bool>,
    pub isolate: Option<bool>,
    #[serde(deserialize_with = "present")]
    pub default_limit: Option<Option<f64>>,
    pub dns: Option<Dns>,
    pub custom_dns: Option<String>,
    pub keep_alive: Option<bool>,
    pub auto_restart: Option<bool>,
}

/// Débit saisi (Mb/s) valide : nombre fini, strictement positif, au plus 10 Gb/s.
pub fn validate_limit(limit: Option<f64>) -> Result<Option<f64>, String> {
    match limit {
        None => Ok(None),
        Some(l) if l.is_finite() && l > 0.0 && l <= 10_000.0 => Ok(Some(l)),
        Some(_) => Err("Débit maximal invalide".into()),
    }
}

/// Mb/s → octets/s (1 Mb/s = 125 000 o/s).
pub fn mbps_to_bytes(mbps: f64) -> u64 {
    // Valeur validée en amont (finie, positive) : la conversion ne peut pas déborder.
    (mbps * 125_000.0).round().max(0.0) as u64
}

/// Lit une adresse IPv4 de résolveur ; message d'erreur prêt à afficher.
pub fn parse_dns(text: &str) -> Result<Ipv4Addr, String> {
    let ip: Ipv4Addr = text
        .trim()
        .parse()
        .map_err(|_| format!("Adresse DNS invalide : « {} »", text.trim()))?;
    if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() {
        return Err(format!("Adresse DNS invalide : « {ip} »"));
    }
    Ok(ip)
}

impl Settings {
    /// Applique `patch` et valide le résultat. L'adresse personnalisée vide est admise (le
    /// résolveur de Windows reste alors utilisé) : l'interface choisit « Personnalisé »
    /// avant de saisir l'adresse.
    pub fn patched(&self, patch: SettingsPatch) -> Result<Settings, String> {
        let mut s = self.clone();
        macro_rules! take {
            ($($field:ident),*) => { $( if let Some(v) = patch.$field { s.$field = v; } )* };
        }
        take!(
            autostart,
            share_on_launch,
            notifications,
            ad_block,
            isolate,
            dns,
            keep_alive,
            auto_restart
        );
        if let Some(limit) = patch.default_limit {
            s.default_limit = validate_limit(limit)?;
        }
        if let Some(custom) = patch.custom_dns {
            let custom = custom.trim();
            if !custom.is_empty() {
                parse_dns(custom)?;
            }
            s.custom_dns = custom.to_owned();
        }
        Ok(s)
    }

    /// Résolveur imposé aux appareils ; `None` = DNS de Windows.
    pub fn dns_upstream(&self) -> Option<Ipv4Addr> {
        match self.dns {
            Dns::Auto => None,
            Dns::Cloudflare => Some(Ipv4Addr::new(1, 1, 1, 1)),
            Dns::Google => Some(Ipv4Addr::new(8, 8, 8, 8)),
            Dns::Custom => parse_dns(&self.custom_dns).ok(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn patch(json: &str) -> SettingsPatch {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn valeurs_par_defaut() {
        let s = Settings::default();
        assert!(s.keep_alive);
        assert!(!s.autostart && !s.share_on_launch && !s.ad_block && !s.auto_restart);
        assert_eq!(s.dns, Dns::Auto);
        assert_eq!(s.default_limit, None);
    }

    #[test]
    fn json_camel_case() {
        let v = serde_json::to_value(Settings::default()).unwrap();
        assert_eq!(v["shareOnLaunch"], false);
        assert_eq!(v["keepAlive"], true);
        assert_eq!(v["defaultLimit"], serde_json::Value::Null);
        assert_eq!(v["dns"], "auto");
        assert_eq!(v["customDns"], "");
        assert!(v.get("sourceId").is_none());
    }

    #[test]
    fn fichier_tolerant() {
        let f: SettingsFile = serde_json::from_str(
            r#"{"adBlock":true,"dns":"inconnu","keepAlive":"oui","defaultLimit":5,"sourceId":"{abc}","x":1}"#,
        )
        .unwrap();
        assert!(f.settings.ad_block);
        assert_eq!(f.settings.dns, Dns::Auto);
        assert!(f.settings.keep_alive);
        assert_eq!(f.settings.default_limit, Some(5.0));
        assert_eq!(f.source_id.as_deref(), Some("{abc}"));

        let f: SettingsFile = serde_json::from_str("{}").unwrap();
        assert_eq!(f, SettingsFile::default());
    }

    #[test]
    fn fichier_aller_retour() {
        let f = SettingsFile {
            settings: Settings {
                dns: Dns::Custom,
                custom_dns: "9.9.9.9".into(),
                default_limit: Some(2.5),
                ..Settings::default()
            },
            source_id: Some("{guid}".into()),
        };
        let text = serde_json::to_string(&f).unwrap();
        assert_eq!(serde_json::from_str::<SettingsFile>(&text).unwrap(), f);
    }

    #[test]
    fn fusion_du_patch() {
        let s = Settings::default();
        let p = s
            .patched(patch(
                r#"{"adBlock":true,"defaultLimit":10,"dns":"google"}"#,
            ))
            .unwrap();
        assert!(p.ad_block);
        assert_eq!(p.default_limit, Some(10.0));
        assert_eq!(p.dns, Dns::Google);
        assert!(p.keep_alive, "champ absent conservé");

        // `null` explicite : illimité ; champ absent : inchangé.
        let q = p.patched(patch(r#"{"defaultLimit":null}"#)).unwrap();
        assert_eq!(q.default_limit, None);
        let r = p.patched(patch("{}")).unwrap();
        assert_eq!(r, p);
    }

    #[test]
    fn patch_invalide_refuse() {
        let s = Settings::default();
        assert!(s.patched(patch(r#"{"customDns":"1.2.3"}"#)).is_err());
        assert!(s.patched(patch(r#"{"customDns":"0.0.0.0"}"#)).is_err());
        assert!(s.patched(patch(r#"{"defaultLimit":0}"#)).is_err());
        assert!(s.patched(patch(r#"{"defaultLimit":-3}"#)).is_err());
        let ok = s
            .patched(patch(r#"{"dns":"custom","customDns":" 9.9.9.9 "}"#))
            .unwrap();
        assert_eq!(ok.custom_dns, "9.9.9.9");
        // Choix « Personnalisé » avant la saisie de l'adresse : accepté.
        assert!(s.patched(patch(r#"{"dns":"custom"}"#)).is_ok());
    }

    #[test]
    fn resolveur_impose() {
        let mut s = Settings::default();
        assert_eq!(s.dns_upstream(), None);
        s.dns = Dns::Cloudflare;
        assert_eq!(s.dns_upstream(), Some(Ipv4Addr::new(1, 1, 1, 1)));
        s.dns = Dns::Google;
        assert_eq!(s.dns_upstream(), Some(Ipv4Addr::new(8, 8, 8, 8)));
        s.dns = Dns::Custom;
        assert_eq!(s.dns_upstream(), None, "adresse vide : DNS de Windows");
        s.custom_dns = "9.9.9.9".into();
        assert_eq!(s.dns_upstream(), Some(Ipv4Addr::new(9, 9, 9, 9)));
    }

    #[test]
    fn conversion_mbps() {
        assert_eq!(mbps_to_bytes(1.0), 125_000);
        assert_eq!(mbps_to_bytes(2.5), 312_500);
        assert_eq!(mbps_to_bytes(25.0), 3_125_000);
        assert_eq!(
            validate_limit(Some(f64::NAN)),
            Err("Débit maximal invalide".into())
        );
        assert_eq!(validate_limit(Some(5.0)), Ok(Some(5.0)));
    }
}
