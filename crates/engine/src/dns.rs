//! Analyse DNS minimale (RFC 1035) en Rust pur : en-tête, première question et fabrication
//! d'une réponse `NXDOMAIN`.
//!
//! Toutes les lectures sont bornées : aucune donnée, même arbitraire, ne provoque de panique.

use thiserror::Error;

/// Port DNS standard.
pub const PORT: u16 = 53;
/// Taille de l'en-tête DNS.
pub const HEADER_LEN: usize = 12;
/// Code de réponse « domaine inexistant ».
pub const RCODE_NXDOMAIN: u16 = 3;

/// Longueur maximale d'un nom sur le fil (étiquettes et zéro final compris).
const MAX_NAME_WIRE_LEN: usize = 255;

const FLAG_QR: u16 = 0x8000;
const OPCODE_MASK: u16 = 0x7800;
const FLAG_RD: u16 = 0x0100;
const FLAG_RA: u16 = 0x0080;
const FLAG_CD: u16 = 0x0010;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DnsError {
    #[error("message DNS tronqué")]
    TooShort,
    #[error("ce n'est pas une requête DNS standard")]
    NotQuery,
    #[error("requête DNS sans question")]
    NoQuestion,
    #[error("nom DNS invalide")]
    BadName,
    #[error("pointeur de compression dans la question")]
    Compressed,
}

/// Requête DNS standard réduite à sa première question.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Query {
    pub id: u16,
    /// Indicateurs de l'en-tête (QR, opcode, RD, CD…).
    pub flags: u16,
    /// Nom de la question en minuscules, étiquettes séparées par des points, sans point
    /// final (`""` pour la racine).
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    /// Fin de la première question dans le message : elle occupe `HEADER_LEN..question_end`.
    pub question_end: usize,
}

fn be16(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off.checked_add(2)?)?;
    Some(u16::from_be_bytes([s[0], s[1]]))
}

/// Identifiant d'un message DNS (deux premiers octets).
pub fn message_id(msg: &[u8]) -> Option<u16> {
    be16(msg, 0)
}

/// `true` si `msg` est une réponse (QR) portant l'identifiant `id`.
pub fn is_response_to(msg: &[u8], id: u16) -> bool {
    msg.len() >= HEADER_LEN
        && message_id(msg) == Some(id)
        && be16(msg, 2).is_some_and(|f| f & FLAG_QR != 0)
}

/// Octet accepté dans une étiquette : ASCII visible, hors point (qui serait ambigu une fois
/// le nom remis sous forme textuelle).
fn is_label_byte(b: u8) -> bool {
    b.is_ascii_graphic() && b != b'.'
}

/// Lit un nom non compressé à partir de `start` ; renvoie le nom textuel et la position qui
/// suit son zéro final.
fn parse_name(msg: &[u8], start: usize) -> Result<(String, usize), DnsError> {
    let mut name = String::new();
    let mut pos = start;
    loop {
        let len = *msg.get(pos).ok_or(DnsError::TooShort)?;
        pos += 1;
        match len {
            0 => break,
            l if l & 0xC0 == 0xC0 => return Err(DnsError::Compressed),
            // Types d'étiquettes étendus (0x40, 0x80) : obsolètes, refusés.
            l if l & 0xC0 != 0 => return Err(DnsError::BadName),
            l => {
                let l = usize::from(l);
                let label = msg.get(pos..pos + l).ok_or(DnsError::TooShort)?;
                pos += l;
                if pos - start >= MAX_NAME_WIRE_LEN {
                    return Err(DnsError::BadName);
                }
                if !label.iter().all(|&b| is_label_byte(b)) {
                    return Err(DnsError::BadName);
                }
                if !name.is_empty() {
                    name.push('.');
                }
                name.extend(label.iter().map(|&b| char::from(b.to_ascii_lowercase())));
            }
        }
    }
    Ok((name, pos))
}

/// Analyse une requête DNS standard (QR = 0, opcode 0) et sa première question. Les noms
/// compressés dans la question sont refusés (jamais utilisés par les clients en pratique).
pub fn parse_query(msg: &[u8]) -> Result<Query, DnsError> {
    if msg.len() < HEADER_LEN {
        return Err(DnsError::TooShort);
    }
    let id = be16(msg, 0).ok_or(DnsError::TooShort)?;
    let flags = be16(msg, 2).ok_or(DnsError::TooShort)?;
    if flags & (FLAG_QR | OPCODE_MASK) != 0 {
        return Err(DnsError::NotQuery);
    }
    if be16(msg, 4).ok_or(DnsError::TooShort)? == 0 {
        return Err(DnsError::NoQuestion);
    }
    let (name, pos) = parse_name(msg, HEADER_LEN)?;
    let qtype = be16(msg, pos).ok_or(DnsError::TooShort)?;
    let qclass = be16(msg, pos + 2).ok_or(DnsError::TooShort)?;
    Ok(Query {
        id,
        flags,
        name,
        qtype,
        qclass,
        question_end: pos + 4,
    })
}

/// Fabrique la réponse `NXDOMAIN` à la requête `msg` analysée en `q` : même identifiant,
/// question recopiée, indicateurs QR et RA (RD et CD repris de la requête), RCODE 3, aucune
/// autre section. `None` si `q` ne correspond pas à `msg`.
pub fn nxdomain(msg: &[u8], q: &Query) -> Option<Vec<u8>> {
    let question = msg.get(HEADER_LEN..q.question_end)?;
    let flags = FLAG_QR | FLAG_RA | (q.flags & (FLAG_RD | FLAG_CD)) | RCODE_NXDOMAIN;
    let mut out = Vec::with_capacity(HEADER_LEN + question.len());
    out.extend_from_slice(&q.id.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&[0; 6]); // ANCOUNT, NSCOUNT, ARCOUNT
    out.extend_from_slice(question);
    Some(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Requête DNS standard (RD posé) pour `name`, type A, classe IN.
    pub(crate) fn query(id: u16, name: &str) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&id.to_be_bytes());
        m.extend_from_slice(&FLAG_RD.to_be_bytes());
        m.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
        for label in name.split('.').filter(|l| !l.is_empty()) {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&[0, 1, 0, 1]);
        m
    }

    #[test]
    fn parses_standard_query() {
        let m = query(0xABCD, "Ads.Example.COM");
        let q = parse_query(&m).unwrap();
        assert_eq!(q.id, 0xABCD);
        assert_eq!(q.name, "ads.example.com");
        assert_eq!((q.qtype, q.qclass), (1, 1));
        assert_eq!(q.question_end, m.len());
        assert_eq!(message_id(&m), Some(0xABCD));
    }

    #[test]
    fn parses_root_and_trailing_sections() {
        let mut m = query(1, "");
        let q = parse_query(&m).unwrap();
        assert_eq!(q.name, "");
        assert_eq!(q.question_end, HEADER_LEN + 5);
        // Une section additionnelle (EDNS) après la question ne gêne pas.
        m[11] = 1;
        m.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0]);
        let q = parse_query(&m).unwrap();
        assert_eq!(q.question_end, HEADER_LEN + 5);
    }

    #[test]
    fn rejects_non_queries() {
        let mut m = query(1, "a.b");
        m[2] |= 0x80; // QR : réponse
        assert_eq!(parse_query(&m), Err(DnsError::NotQuery));
        let mut m = query(1, "a.b");
        m[2] |= 0x28; // opcode 5 (UPDATE)
        assert_eq!(parse_query(&m), Err(DnsError::NotQuery));
        let mut m = query(1, "a.b");
        m[5] = 0; // QDCOUNT = 0
        assert_eq!(parse_query(&m), Err(DnsError::NoQuestion));
    }

    #[test]
    fn rejects_malformed_names() {
        let base = query(1, "a.b");
        // Pointeur de compression.
        let mut m = base[..HEADER_LEN].to_vec();
        m.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1]);
        assert_eq!(parse_query(&m), Err(DnsError::Compressed));
        // Type d'étiquette étendu.
        let mut m = base[..HEADER_LEN].to_vec();
        m.extend_from_slice(&[0x41, b'a', 0, 0, 1, 0, 1]);
        assert_eq!(parse_query(&m), Err(DnsError::BadName));
        // Point ou octet non imprimable dans une étiquette.
        assert_eq!(parse_query(&query(1, "a b.c")), Err(DnsError::BadName));
        let mut m = base[..HEADER_LEN].to_vec();
        m.extend_from_slice(&[3, b'a', b'.', b'b', 0, 0, 1, 0, 1]);
        assert_eq!(parse_query(&m), Err(DnsError::BadName));
        // Nom trop long (> 255 octets sur le fil).
        let long = vec!["abcdefghij"; 26].join(".");
        assert_eq!(parse_query(&query(1, &long)), Err(DnsError::BadName));
        // Limite exacte : 3 étiquettes de 63 + 1 de 61 = 3*64 + 62 + zéro final = 255 octets.
        let name = |last: usize| {
            [
                &"a".repeat(63)[..],
                &"b".repeat(63),
                &"c".repeat(63),
                &"d".repeat(last),
            ]
            .join(".")
        };
        assert!(parse_query(&query(1, &name(61))).is_ok());
        assert_eq!(parse_query(&query(1, &name(62))), Err(DnsError::BadName));
    }

    #[test]
    fn truncated_messages_never_panic() {
        let m = query(7, "tracker.example.net");
        for len in 0..m.len() {
            assert!(parse_query(&m[..len]).is_err(), "longueur {len}");
        }
        assert!(parse_query(&m).is_ok());
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        // Générateur pseudo-aléatoire déterministe (xorshift).
        let mut x: u32 = 0x1234_5678;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x
        };
        for _ in 0..5_000 {
            let len = (next() % 300) as usize;
            let mut m: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            if m.len() > 5 {
                m[2] &= 0x07; // le plus souvent une requête standard
                m[4] = 0;
                m[5] = 1;
            }
            if let Ok(q) = parse_query(&m) {
                let r = nxdomain(&m, &q).expect("question cohérente");
                assert!(
                    parse_query(&r).is_err(),
                    "une réponse n'est pas une requête"
                );
            }
            let _ = is_response_to(&m, 0);
        }
    }

    #[test]
    fn builds_nxdomain_response() {
        let m = query(0x4242, "ads.example.com");
        let q = parse_query(&m).unwrap();
        let r = nxdomain(&m, &q).unwrap();
        assert_eq!(r.len(), m.len());
        assert_eq!(&r[0..2], &[0x42, 0x42]);
        let flags = u16::from_be_bytes([r[2], r[3]]);
        assert_eq!(flags & FLAG_QR, FLAG_QR);
        assert_eq!(flags & FLAG_RA, FLAG_RA);
        assert_eq!(flags & FLAG_RD, FLAG_RD, "RD repris de la requête");
        assert_eq!(flags & OPCODE_MASK, 0);
        assert_eq!(flags & 0x000F, RCODE_NXDOMAIN);
        assert_eq!(&r[4..12], &[0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&r[12..], &m[12..q.question_end]);
        assert!(is_response_to(&r, 0x4242));
        assert!(!is_response_to(&r, 0x4243));
        assert!(
            !is_response_to(&m, 0x4242),
            "la requête n'est pas une réponse"
        );
    }

    #[test]
    fn nxdomain_drops_additional_sections_and_checks_bounds() {
        let mut m = query(9, "x.y");
        m[11] = 1;
        m.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0]);
        let q = parse_query(&m).unwrap();
        let r = nxdomain(&m, &q).unwrap();
        assert_eq!(r.len(), q.question_end);
        // Requête ne correspondant pas au message : pas de panique.
        assert_eq!(nxdomain(&m[..10], &q), None);
    }
}
