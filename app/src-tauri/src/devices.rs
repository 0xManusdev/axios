//! Appareils : préférences persistées (`devices.json`), type deviné, nom affiché.

use std::{collections::BTreeMap, net::Ipv4Addr};

use serde::{Deserialize, Serialize};

use crate::store::lenient;

/// Longueur maximale d'un nom choisi par l'utilisateur, en caractères.
const ALIAS_MAX_CHARS: usize = 64;

/// Type d'appareil affiché par l'interface.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceKind {
    Phone,
    Laptop,
    Tablet,
    Tv,
    #[default]
    Other,
}

/// Mots-clés recherchés dans le nom d'hôte, par ordre de priorité.
const KIND_RULES: [(DeviceKind, &[&str]); 4] = [
    (DeviceKind::Tablet, &["ipad", "tab", "tablet"]),
    (
        DeviceKind::Phone,
        &[
            "iphone", "android", "galaxy", "pixel", "redmi", "xiaomi", "oppo", "huawei", "tecno",
            "infinix", "phone", "sm-",
        ],
    ),
    (
        DeviceKind::Tv,
        &["tv", "bravia", "roku", "chromecast", "firetv"],
    ),
    (
        DeviceKind::Laptop,
        &[
            "macbook", "laptop", "desktop", "pc", "book", "thinkpad", "dell", "hp-", "lenovo",
        ],
    ),
];

/// Devine le type d'appareil d'après son nom d'hôte (insensible à la casse).
pub fn guess_kind(hostname: &str) -> DeviceKind {
    let name = hostname.to_lowercase();
    if name.trim().is_empty() {
        return DeviceKind::Other;
    }
    KIND_RULES
        .iter()
        .find(|(_, words)| words.iter().any(|w| name.contains(w)))
        .map_or(DeviceKind::Other, |(kind, _)| *kind)
}

/// Fabricant affiché : table OUI, « Adresse privée » pour une MAC aléatoire, sinon vide.
pub fn vendor_label(mac: Option<&str>) -> String {
    let Some(mac) = mac else {
        return String::new();
    };
    if let Some(vendor) = pw_winsys::mac::vendor(mac) {
        vendor.to_owned()
    } else if pw_winsys::mac::is_private(mac) {
        "Adresse privée".to_owned()
    } else {
        String::new()
    }
}

/// Nom affiché d'un appareil : nom choisi, nom d'hôte, fabricant, sinon identifiant.
pub fn display_name(id: &str, alias: &str, hostname: &str, vendor: &str) -> String {
    if !alias.trim().is_empty() {
        alias.trim().to_owned()
    } else if !hostname.trim().is_empty() {
        hostname.trim().to_owned()
    } else if !vendor.is_empty() && vendor != "Adresse privée" {
        format!("Appareil {vendor}")
    } else {
        id.to_owned()
    }
}

/// Normalise un identifiant d'appareil : MAC en `AA:BB:CC:DD:EE:FF`, sinon texte nettoyé.
pub fn normalize_id(id: &str) -> String {
    id.trim().replace('-', ":").to_ascii_uppercase()
}

/// Préférences d'un appareil.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DeviceEntry {
    #[serde(deserialize_with = "lenient", skip_serializing_if = "String::is_empty")]
    pub alias: String,
    #[serde(
        deserialize_with = "lenient",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub blocked: bool,
    /// Débit maximal propre (Mb/s), `None` = réglage par défaut.
    #[serde(deserialize_with = "lenient", skip_serializing_if = "Option::is_none")]
    pub limit: Option<f64>,
    /// Dernier nom d'hôte connu (nom des appareils absents dans l'historique).
    #[serde(deserialize_with = "lenient", skip_serializing_if = "String::is_empty")]
    pub hostname: String,
}

impl DeviceEntry {
    fn is_empty(&self) -> bool {
        *self == DeviceEntry::default()
    }
}

/// Contenu de `devices.json` : préférences par identifiant (MAC, sinon IP).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeviceStore {
    pub entries: BTreeMap<String, DeviceEntry>,
}

impl DeviceStore {
    pub fn get(&self, id: &str) -> Option<&DeviceEntry> {
        self.entries.get(id)
    }

    /// Modifie l'entrée `id` (créée au besoin, retirée si elle redevient vide). Renvoie
    /// `true` si quelque chose a changé.
    pub fn edit(&mut self, id: &str, f: impl FnOnce(&mut DeviceEntry)) -> bool {
        let before = self.entries.get(id).cloned();
        let mut entry = before.clone().unwrap_or_default();
        f(&mut entry);
        let after = (!entry.is_empty()).then_some(entry);
        if after == before {
            return false;
        }
        match after {
            Some(entry) => self.entries.insert(id.to_owned(), entry),
            None => self.entries.remove(id),
        };
        true
    }

    pub fn set_alias(&mut self, id: &str, alias: &str) -> bool {
        let alias: String = alias.trim().chars().take(ALIAS_MAX_CHARS).collect();
        self.edit(id, |e| e.alias = alias)
    }

    pub fn set_blocked(&mut self, id: &str, blocked: bool) -> bool {
        self.edit(id, |e| e.blocked = blocked)
    }

    pub fn set_limit(&mut self, id: &str, limit: Option<f64>) -> bool {
        self.edit(id, |e| e.limit = limit)
    }

    /// Mémorise le nom d'hôte d'un appareil identifié par sa MAC (pas par une IP, qui change).
    pub fn remember_hostname(&mut self, id: &str, hostname: &str) -> bool {
        let hostname = hostname.trim();
        if hostname.is_empty() || id.parse::<Ipv4Addr>().is_ok() {
            return false;
        }
        self.edit(id, |e| hostname.clone_into(&mut e.hostname))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_devine() {
        let cases = [
            ("iPad-de-Lea", DeviceKind::Tablet),
            ("Galaxy-Tab-S8", DeviceKind::Tablet),
            ("iPhone", DeviceKind::Phone),
            ("Galaxy-S23", DeviceKind::Phone),
            ("TECNO-SPARK-10", DeviceKind::Phone),
            ("SM-A515F", DeviceKind::Phone),
            ("Redmi-Note-12", DeviceKind::Phone),
            ("android-3f2a", DeviceKind::Phone),
            ("BRAVIA-4K", DeviceKind::Tv),
            ("Chromecast", DeviceKind::Tv),
            ("Samsung-TV", DeviceKind::Tv),
            ("MacBook-Air", DeviceKind::Laptop),
            ("DESKTOP-8KQ2L", DeviceKind::Laptop),
            ("LAPTOP-AB12", DeviceKind::Laptop),
            ("HP-Envy", DeviceKind::Laptop),
            ("ThinkPad-X1", DeviceKind::Laptop),
            ("", DeviceKind::Other),
            ("raspberry", DeviceKind::Other),
        ];
        for (name, kind) in cases {
            assert_eq!(guess_kind(name), kind, "{name}");
        }
    }

    #[test]
    fn json_du_type() {
        assert_eq!(serde_json::to_value(DeviceKind::Tv).unwrap(), "tv");
        assert_eq!(serde_json::to_value(DeviceKind::Laptop).unwrap(), "laptop");
    }

    #[test]
    fn nom_affiche() {
        assert_eq!(display_name("ID", " Tel ", "host", "Apple"), "Tel");
        assert_eq!(display_name("ID", "", "host", "Apple"), "host");
        assert_eq!(display_name("ID", "", "", "Apple"), "Appareil Apple");
        assert_eq!(display_name("ID", "", "", "Adresse privée"), "ID");
        assert_eq!(display_name("ID", "", "", ""), "ID");
    }

    #[test]
    fn fabricant() {
        assert_eq!(vendor_label(None), "");
        // Bit « administré localement » : adresse aléatoire.
        assert_eq!(vendor_label(Some("02:11:22:33:44:55")), "Adresse privée");
    }

    #[test]
    fn identifiant_normalise() {
        assert_eq!(normalize_id(" aa-bb-cc-dd-ee-ff "), "AA:BB:CC:DD:EE:FF");
        assert_eq!(normalize_id("192.168.137.4"), "192.168.137.4");
    }

    #[test]
    fn entree_retiree_quand_vide() {
        let mut s = DeviceStore::default();
        assert!(s.set_blocked("M", true));
        assert!(!s.set_blocked("M", true), "aucun changement");
        assert!(s.set_limit("M", Some(5.0)));
        assert!(s.set_blocked("M", false));
        assert!(s.set_limit("M", None));
        assert!(s.entries.is_empty());
    }

    #[test]
    fn alias_nettoye_et_borne() {
        let mut s = DeviceStore::default();
        s.set_alias("M", &format!("  {}  ", "x".repeat(100)));
        assert_eq!(s.get("M").unwrap().alias.len(), ALIAS_MAX_CHARS);
        s.set_alias("M", "   ");
        assert!(s.get("M").is_none());
    }

    #[test]
    fn nom_d_hote_par_mac_uniquement() {
        let mut s = DeviceStore::default();
        assert!(!s.remember_hostname("192.168.137.9", "tel"));
        assert!(s.remember_hostname("AA:BB:CC:DD:EE:FF", "tel"));
        assert!(!s.remember_hostname("AA:BB:CC:DD:EE:FF", "tel"));
        assert!(!s.remember_hostname("AA:BB:CC:DD:EE:FF", ""));
    }

    #[test]
    fn fichier_tolerant() {
        let s: DeviceStore = serde_json::from_str(
            r#"{"AA:BB:CC:DD:EE:01":{"alias":"Tel","blocked":true,"limit":5},
                "AA:BB:CC:DD:EE:02":{"blocked":"oui","limit":"x","autre":1}}"#,
        )
        .unwrap();
        let a = s.get("AA:BB:CC:DD:EE:01").unwrap();
        assert_eq!(
            (a.alias.as_str(), a.blocked, a.limit),
            ("Tel", true, Some(5.0))
        );
        let b = s.get("AA:BB:CC:DD:EE:02").unwrap();
        assert_eq!((b.blocked, b.limit), (false, None));
        let text = serde_json::to_string(&s).unwrap();
        assert!(!text.contains("hostname"), "champs vides omis : {text}");
    }
}
