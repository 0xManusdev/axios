//! Adresses MAC : formatage, adresse privée, fabricant (OUI).

use crate::oui::OUI;

/// Octets -> `"AA:BB:CC:DD:EE:FF"`.
pub(crate) fn format_mac(bytes: &[u8]) -> String {
    let parts: Vec<String> = bytes.iter().map(|b| format!("{b:02X}")).collect();
    parts.join(":")
}

/// Lit une MAC textuelle (`aa-bb-…`, `aabbcc…`, `aa:bb:…`, `aabb.ccdd.eeff`) ; `None` si ce
/// n'est pas une MAC de 12 chiffres hexadécimaux.
fn parse_mac(text: &str) -> Option<[u8; 6]> {
    let digits: Vec<u8> = text
        .chars()
        .filter(|c| !matches!(c, ':' | '-' | '.' | ' '))
        .map(|c| c.to_digit(16).and_then(|d| u8::try_from(d).ok()))
        .collect::<Option<_>>()?;
    if digits.len() != 12 {
        return None;
    }
    let mut bytes = [0u8; 6];
    for (byte, &[hi, lo]) in bytes.iter_mut().zip(digits.as_chunks::<2>().0) {
        *byte = (hi << 4) | lo;
    }
    Some(bytes)
}

/// Normalise une MAC textuelle (`aa-bb-…`, `aabbcc…`, `aa:bb:…`) en `"AA:BB:CC:DD:EE:FF"`.
/// Une chaîne qui n'est pas une MAC de 12 chiffres hexadécimaux est renvoyée en majuscules.
pub(crate) fn normalize_mac(text: &str) -> String {
    match parse_mac(text) {
        Some(bytes) => format_mac(&bytes),
        None => text.trim().to_uppercase(),
    }
}

/// Bit « administré localement » du premier octet.
const LOCAL_BIT: u8 = 0x02;
/// Bit « multidiffusion » du premier octet.
const MULTICAST_BIT: u8 = 0x01;

/// Adresse privée (bit « administré localement ») : MAC aléatoire des téléphones récents.
/// `false` si le texte n'est pas une MAC.
pub fn is_private(mac: &str) -> bool {
    parse_mac(mac).is_some_and(|b| b[0] & LOCAL_BIT != 0)
}

/// Fabricant d'après le préfixe OUI (table courte embarquée, extraite du registre IEEE).
/// `None` si inconnu, privée, multidiffusion ou invalide.
pub fn vendor(mac: &str) -> Option<&'static str> {
    let b = parse_mac(mac)?;
    if b[0] & (LOCAL_BIT | MULTICAST_BIT) != 0 {
        return None;
    }
    let prefix = u32::from_be_bytes([0, b[0], b[1], b[2]]);
    OUI.binary_search_by_key(&prefix, |&(p, _)| p)
        .ok()
        .map(|i| OUI[i].1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_bytes() {
        assert_eq!(
            format_mac(&[0x0a, 0xbb, 0x00, 0x1f, 0xe0, 0xff]),
            "0A:BB:00:1F:E0:FF"
        );
        assert_eq!(format_mac(&[]), "");
    }

    #[test]
    fn normalizes_text() {
        for s in ["aabbccddeeff", "aa-bb-cc-dd-ee-ff", "AA:bb:CC:dd:EE:ff"] {
            assert_eq!(normalize_mac(s), "AA:BB:CC:DD:EE:FF");
        }
        assert_eq!(normalize_mac("pas une mac"), "PAS UNE MAC");
        assert_eq!(normalize_mac("aabb"), "AABB");
    }

    #[test]
    fn parses_formats() {
        let expected = Some([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        for s in [
            "aabbccddeeff",
            "AA-BB-CC-DD-EE-FF",
            "aa:bb:cc:dd:ee:ff",
            "aabb.ccdd.eeff",
        ] {
            assert_eq!(parse_mac(s), expected, "{s}");
        }
        assert_eq!(parse_mac(""), None);
        assert_eq!(parse_mac("aa:bb:cc:dd:ee"), None);
        assert_eq!(parse_mac("aa:bb:cc:dd:ee:ff:00"), None);
        assert_eq!(parse_mac("gg:bb:cc:dd:ee:ff"), None);
        assert_eq!(parse_mac("é"), None);
    }

    #[test]
    fn private_bit() {
        // Deuxième chiffre hexadécimal 2, 6, A ou E : administrée localement.
        for s in [
            "02:00:00:00:00:01",
            "DA:A1:19:12:34:56",
            "f6:11:22:33:44:55",
            "3e-00-00-00-00-00",
        ] {
            assert!(is_private(s), "{s}");
        }
        for s in [
            "00:03:93:12:34:56",
            "F0:18:98:00:00:00",
            "01:00:5E:00:00:01",
            "pas une mac",
            "",
        ] {
            assert!(!is_private(s), "{s}");
        }
    }

    #[test]
    fn known_vendors() {
        for (mac, name) in [
            ("00:03:93:12:34:56", "Apple"),
            ("f0-18-98-aa-bb-cc", "Apple"),
            ("8C:77:12:00:00:01", "Samsung"),
            ("8cbebe000001", "Xiaomi"),
            ("00:E0:FC:01:02:03", "Huawei"),
            ("2C:5B:B8:01:02:03", "Oppo"),
            ("94:65:2D:01:02:03", "OnePlus"),
            ("3C:5A:B4:01:02:03", "Google"),
            ("00:1B:21:01:02:03", "Intel"),
            ("00:E0:4C:68:00:01", "Realtek"),
            ("00:15:5D:01:02:03", "Microsoft"),
            ("00:09:BF:01:02:03", "Nintendo"),
            ("B8:27:EB:01:02:03", "Raspberry Pi"),
            ("DC:A6:32:01:02:03", "Raspberry Pi"),
        ] {
            assert_eq!(vendor(mac), Some(name), "{mac}");
        }
    }

    #[test]
    fn unknown_private_or_invalid_vendor() {
        assert_eq!(vendor("12:34:56:78:9A:BC"), None); // privée
        assert_eq!(vendor("01:00:5E:00:00:01"), None); // multidiffusion
        assert_eq!(vendor("FF:FF:FF:FF:FF:FF"), None);
        assert_eq!(vendor("00:00:01:00:00:00"), None); // préfixe absent de la table
        assert_eq!(vendor("pas une mac"), None);
    }

    #[test]
    fn table_is_sorted_unique_and_well_formed() {
        assert!(
            OUI.windows(2).all(|w| w[0].0 < w[1].0),
            "table non triée ou doublon"
        );
        for &(prefix, name) in OUI {
            assert!(prefix <= 0xFF_FFFF, "{prefix:06X}");
            // Un OUI attribué n'a ni le bit local ni le bit multidiffusion.
            assert_eq!((prefix >> 16) & 0x03, 0, "{prefix:06X}");
            assert!(!name.is_empty());
        }
        // Plusieurs préfixes par fabricant.
        for name in [
            "Apple", "Samsung", "Xiaomi", "Huawei", "Honor", "Oppo", "Vivo", "Realme", "Google",
            "Intel",
        ] {
            let n = OUI.iter().filter(|&&(_, v)| v == name).count();
            assert!(n >= 8, "{name} : {n}");
        }
    }
}
