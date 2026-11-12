//! Manipulation de paquets IPv4/TCP/UDP en Rust pur : analyse, réécriture d'adresses et de
//! ports, sommes de contrôle, fabrication de datagrammes UDP et fragmentation IPv4.
//!
//! Aucune dépendance à WinDivert : toute cette logique est testable unitairement.

use std::net::{Ipv4Addr, SocketAddrV4};

use thiserror::Error;

pub const IPV4_HEADER_LEN: usize = 20;
pub const UDP_HEADER_LEN: usize = 8;
/// Taille maximale de la charge utile d'un datagramme UDP sur IPv4.
pub const MAX_UDP_PAYLOAD: usize = 65_535 - IPV4_HEADER_LEN - UDP_HEADER_LEN;
/// MTU Ethernet utilisée pour les paquets fabriqués vers le téléphone.
pub const DEFAULT_MTU: usize = 1500;

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const TCP_MIN_HEADER_LEN: usize = 20;

/// Indicateurs TCP (octet 13 de l'en-tête).
pub mod tcp_flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const ACK: u8 = 0x10;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

/// Résumé d'un paquet IPv4 TCP/UDP non fragmenté.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketInfo {
    /// Longueur de l'en-tête IPv4 (options comprises).
    pub ihl: usize,
    /// Longueur totale annoncée par l'en-tête IPv4.
    pub total_len: usize,
    pub proto: Proto,
    pub src: SocketAddrV4,
    pub dst: SocketAddrV4,
    /// Indicateurs TCP (0 pour UDP).
    pub tcp_flags: u8,
}

impl PacketInfo {
    /// SYN sans ACK : ouverture d'une connexion TCP.
    pub fn is_syn(&self) -> bool {
        self.proto == Proto::Tcp
            && self.tcp_flags & tcp_flags::SYN != 0
            && self.tcp_flags & tcp_flags::ACK == 0
    }

    /// Octets de charge utile UDP de `pkt` (vide pour TCP).
    pub fn udp_payload<'a>(&self, pkt: &'a [u8]) -> &'a [u8] {
        match self.proto {
            Proto::Udp => &pkt[self.ihl + UDP_HEADER_LEN..self.total_len],
            Proto::Tcp => &[],
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("paquet trop court")]
    TooShort,
    #[error("ce n'est pas un paquet IPv4")]
    NotIpv4,
    #[error("en-tête IPv4 invalide")]
    BadHeader,
    #[error("fragment IPv4 non pris en charge")]
    Fragment,
    #[error("protocole {0} non pris en charge")]
    UnsupportedProtocol(u8),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BuildError {
    #[error("datagramme UDP trop grand ({0} octets)")]
    TooLarge(usize),
    #[error("MTU {0} trop petite")]
    BadMtu(usize),
}

fn be16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}

fn ipv4_at(b: &[u8], off: usize) -> Ipv4Addr {
    Ipv4Addr::new(b[off], b[off + 1], b[off + 2], b[off + 3])
}

/// Longueur du premier paquet IPv4 de `buf` (pour découper un lot WinDivert), ou `None` si
/// l'en-tête est incohérent ou le paquet tronqué.
pub fn packet_len(buf: &[u8]) -> Option<usize> {
    if buf.len() < IPV4_HEADER_LEN || buf[0] >> 4 != 4 {
        return None;
    }
    let total = usize::from(be16(buf, 2));
    (IPV4_HEADER_LEN..=buf.len())
        .contains(&total)
        .then_some(total)
}

/// Analyse un paquet IPv4 TCP ou UDP complet (non fragmenté).
pub fn parse(pkt: &[u8]) -> Result<PacketInfo, ParseError> {
    if pkt.len() < IPV4_HEADER_LEN {
        return Err(ParseError::TooShort);
    }
    if pkt[0] >> 4 != 4 {
        return Err(ParseError::NotIpv4);
    }
    let ihl = usize::from(pkt[0] & 0x0F) * 4;
    let total_len = usize::from(be16(pkt, 2));
    if ihl < IPV4_HEADER_LEN || total_len < ihl || total_len > pkt.len() {
        return Err(ParseError::BadHeader);
    }
    // MF ou décalage non nul : fragment.
    if be16(pkt, 6) & 0x3FFF != 0 {
        return Err(ParseError::Fragment);
    }
    let (proto, min_l4) = match pkt[9] {
        PROTO_TCP => (Proto::Tcp, TCP_MIN_HEADER_LEN),
        PROTO_UDP => (Proto::Udp, UDP_HEADER_LEN),
        other => return Err(ParseError::UnsupportedProtocol(other)),
    };
    if total_len < ihl + min_l4 {
        return Err(ParseError::TooShort);
    }
    let l4 = ihl;
    Ok(PacketInfo {
        ihl,
        total_len,
        proto,
        src: SocketAddrV4::new(ipv4_at(pkt, 12), be16(pkt, l4)),
        dst: SocketAddrV4::new(ipv4_at(pkt, 16), be16(pkt, l4 + 2)),
        tcp_flags: if proto == Proto::Tcp { pkt[l4 + 13] } else { 0 },
    })
}

/// Remplace l'adresse et le port source. Les sommes de contrôle ne sont pas mises à jour
/// (voir [`fix_checksums`]).
pub fn set_src(pkt: &mut [u8], info: &PacketInfo, addr: SocketAddrV4) {
    pkt[12..16].copy_from_slice(&addr.ip().octets());
    pkt[info.ihl..info.ihl + 2].copy_from_slice(&addr.port().to_be_bytes());
}

/// Remplace l'adresse et le port destination (sommes de contrôle non mises à jour).
pub fn set_dst(pkt: &mut [u8], info: &PacketInfo, addr: SocketAddrV4) {
    pkt[16..20].copy_from_slice(&addr.ip().octets());
    pkt[info.ihl + 2..info.ihl + 4].copy_from_slice(&addr.port().to_be_bytes());
}

/// Accumulateur de somme de contrôle Internet (RFC 1071).
///
/// Tous les fragments ajoutés, sauf le dernier, doivent avoir une longueur paire.
#[derive(Default)]
struct Sum(u64);

impl Sum {
    fn add(&mut self, data: &[u8]) {
        let (words, rest) = data.as_chunks::<4>();
        for w in words {
            self.0 += u64::from(u32::from_be_bytes(*w));
        }
        if !rest.is_empty() {
            let mut w = [0u8; 4];
            w[..rest.len()].copy_from_slice(rest);
            self.0 += u64::from(u32::from_be_bytes(w));
        }
    }

    /// Somme repliée sur 16 bits, non complémentée.
    fn folded(&self) -> u16 {
        let mut s = self.0;
        while s > 0xFFFF {
            s = (s & 0xFFFF) + (s >> 16);
        }
        s as u16
    }

    fn finish(&self) -> u16 {
        !self.folded()
    }
}

fn pseudo_header_sum(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, l4_len: usize) -> Sum {
    let mut s = Sum::default();
    s.add(&src.octets());
    s.add(&dst.octets());
    s.add(&[0, proto]);
    s.add(&(l4_len as u16).to_be_bytes());
    s
}

/// Somme de contrôle d'un en-tête IPv4 dont le champ de somme est à zéro.
pub fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut s = Sum::default();
    s.add(header);
    s.finish()
}

/// Somme de contrôle TCP/UDP d'un segment dont le champ de somme est à zéro.
/// Pour UDP, un résultat nul est transmis sous la forme `0xFFFF` (RFC 768).
pub fn l4_checksum(src: Ipv4Addr, dst: Ipv4Addr, proto: Proto, segment: &[u8]) -> u16 {
    let num = match proto {
        Proto::Tcp => PROTO_TCP,
        Proto::Udp => PROTO_UDP,
    };
    let mut s = pseudo_header_sum(src, dst, num, segment.len());
    s.add(segment);
    match (s.finish(), proto) {
        (0, Proto::Udp) => 0xFFFF,
        (c, _) => c,
    }
}

/// Recalcule les sommes de contrôle IPv4 et TCP/UDP de `pkt` (adresses lues dans le paquet).
pub fn fix_checksums(pkt: &mut [u8], info: &PacketInfo) {
    let ihl = info.ihl;
    pkt[10..12].fill(0);
    let ip_ck = ipv4_header_checksum(&pkt[..ihl]);
    pkt[10..12].copy_from_slice(&ip_ck.to_be_bytes());

    let ck_off = ihl
        + match info.proto {
            Proto::Tcp => 16,
            Proto::Udp => 6,
        };
    pkt[ck_off..ck_off + 2].fill(0);
    let ck = l4_checksum(
        ipv4_at(pkt, 12),
        ipv4_at(pkt, 16),
        info.proto,
        &pkt[ihl..info.total_len],
    );
    pkt[ck_off..ck_off + 2].copy_from_slice(&ck.to_be_bytes());
}

/// Vérifie les sommes de contrôle IPv4 et TCP/UDP d'un paquet complet.
pub fn checksums_valid(pkt: &[u8], info: &PacketInfo) -> bool {
    let mut ip = Sum::default();
    ip.add(&pkt[..info.ihl]);
    if ip.folded() != 0xFFFF {
        return false;
    }
    let num = match info.proto {
        Proto::Tcp => PROTO_TCP,
        Proto::Udp => PROTO_UDP,
    };
    let seg = &pkt[info.ihl..info.total_len];
    // UDP : une somme transmise à zéro signifie « pas de somme de contrôle ».
    if info.proto == Proto::Udp && be16(seg, 6) == 0 {
        return true;
    }
    let mut s = pseudo_header_sum(*info.src.ip(), *info.dst.ip(), num, seg.len());
    s.add(seg);
    s.folded() == 0xFFFF
}

/// Paramètres d'un datagramme UDP à fabriquer.
#[derive(Clone, Copy, Debug)]
pub struct UdpDatagram<'a> {
    pub src: SocketAddrV4,
    pub dst: SocketAddrV4,
    pub ident: u16,
    pub ttl: u8,
    pub payload: &'a [u8],
}

fn push_ipv4_header(out: &mut Vec<u8>, total_len: usize, d: &UdpDatagram<'_>, flags_frag: u16) {
    let mut h = [0u8; IPV4_HEADER_LEN];
    h[0] = 0x45;
    h[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    h[4..6].copy_from_slice(&d.ident.to_be_bytes());
    h[6..8].copy_from_slice(&flags_frag.to_be_bytes());
    h[8] = d.ttl;
    h[9] = PROTO_UDP;
    h[12..16].copy_from_slice(&d.src.ip().octets());
    h[16..20].copy_from_slice(&d.dst.ip().octets());
    let ck = ipv4_header_checksum(&h);
    h[10..12].copy_from_slice(&ck.to_be_bytes());
    out.extend_from_slice(&h);
}

/// Ajoute à `out` le ou les paquets IPv4 portant le datagramme UDP `d`, fragmentés pour
/// respecter `mtu`. Les paquets sont écrits bout à bout (format d'un lot WinDivert).
/// Retourne le nombre de paquets ajoutés. Les fragments partagent le même identifiant ;
/// la somme de contrôle UDP est calculée sur le datagramme entier (dans le 1er fragment).
pub fn append_udp_packets(
    out: &mut Vec<u8>,
    d: &UdpDatagram<'_>,
    mtu: usize,
) -> Result<usize, BuildError> {
    if mtu < 68 {
        return Err(BuildError::BadMtu(mtu));
    }
    if d.payload.len() > MAX_UDP_PAYLOAD {
        return Err(BuildError::TooLarge(d.payload.len()));
    }
    let udp_len = UDP_HEADER_LEN + d.payload.len();

    let mut hdr = [0u8; UDP_HEADER_LEN];
    hdr[0..2].copy_from_slice(&d.src.port().to_be_bytes());
    hdr[2..4].copy_from_slice(&d.dst.port().to_be_bytes());
    hdr[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    let mut sum = pseudo_header_sum(*d.src.ip(), *d.dst.ip(), PROTO_UDP, udp_len);
    sum.add(&hdr);
    sum.add(d.payload);
    let ck = match sum.finish() {
        0 => 0xFFFF,
        c => c,
    };
    hdr[6..8].copy_from_slice(&ck.to_be_bytes());

    // Copie la tranche [from, to) du datagramme (en-tête UDP puis charge utile).
    let extend = |out: &mut Vec<u8>, from: usize, to: usize| {
        if from < UDP_HEADER_LEN {
            out.extend_from_slice(&hdr[from..to.min(UDP_HEADER_LEN)]);
        }
        if to > UDP_HEADER_LEN {
            let start = from.max(UDP_HEADER_LEN) - UDP_HEADER_LEN;
            out.extend_from_slice(&d.payload[start..to - UDP_HEADER_LEN]);
        }
    };

    if IPV4_HEADER_LEN + udp_len <= mtu {
        out.reserve(IPV4_HEADER_LEN + udp_len);
        push_ipv4_header(out, IPV4_HEADER_LEN + udp_len, d, 0);
        extend(out, 0, udp_len);
        return Ok(1);
    }

    // Charge utile maximale par fragment : multiple de 8 octets.
    let chunk = (mtu - IPV4_HEADER_LEN) / 8 * 8;
    let mut offset = 0;
    let mut count = 0;
    while offset < udp_len {
        let n = chunk.min(udp_len - offset);
        let more = offset + n < udp_len;
        let flags_frag = (if more { 0x2000 } else { 0 }) | (offset / 8) as u16;
        out.reserve(IPV4_HEADER_LEN + n);
        push_ipv4_header(out, IPV4_HEADER_LEN + n, d, flags_frag);
        extend(out, offset, offset + n);
        offset += n;
        count += 1;
    }
    Ok(count)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Référence naïve (mot de 16 bits par mot de 16 bits), indépendante de [`Sum`].
    fn naive_checksum(parts: &[&[u8]]) -> u16 {
        let bytes: Vec<u8> = parts.concat();
        let mut sum: u32 = 0;
        for pair in bytes.chunks(2) {
            let w = if pair.len() == 2 {
                u16::from_be_bytes([pair[0], pair[1]])
            } else {
                u16::from_be_bytes([pair[0], 0])
            };
            sum += u32::from(w);
        }
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// Construit un paquet TCP minimal (20 + 20 octets + charge) avec sommes valides.
    pub(crate) fn tcp_packet(
        src: SocketAddrV4,
        dst: SocketAddrV4,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let total = 40 + payload.len();
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        p[6] = 0x40; // DF
        p[8] = 1; // TTL 1, comme le routeur amont
        p[9] = PROTO_TCP;
        p[12..16].copy_from_slice(&src.ip().octets());
        p[16..20].copy_from_slice(&dst.ip().octets());
        p[20..22].copy_from_slice(&src.port().to_be_bytes());
        p[22..24].copy_from_slice(&dst.port().to_be_bytes());
        p[24..28].copy_from_slice(&1000u32.to_be_bytes());
        p[28..32].copy_from_slice(&2000u32.to_be_bytes());
        p[32] = 0x50;
        p[33] = flags;
        p[34..36].copy_from_slice(&65535u16.to_be_bytes());
        p.extend_from_slice(payload);
        let info = parse(&p).unwrap();
        fix_checksums(&mut p, &info);
        p
    }

    pub(crate) fn sa(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port)
    }

    #[test]
    fn ipv4_checksum_known_value() {
        // Exemple classique (Wikipedia) : somme attendue 0xB861.
        let hdr = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xC0, 0xA8,
            0x00, 0x01, 0xC0, 0xA8, 0x00, 0xC7,
        ];
        assert_eq!(ipv4_header_checksum(&hdr), 0xB861);
    }

    #[test]
    fn checksum_matches_naive_reference_for_all_lengths() {
        let data: Vec<u8> = (0..300u32).map(|i| (i * 37 + 11) as u8).collect();
        for len in 0..data.len() {
            let mut s = Sum::default();
            s.add(&data[..len]);
            assert_eq!(s.finish(), naive_checksum(&[&data[..len]]), "len {len}");
        }
        // Données 0xFF : forte retenue.
        let ff = vec![0xFFu8; 1501];
        let mut s = Sum::default();
        s.add(&ff);
        assert_eq!(s.finish(), naive_checksum(&[&ff]));
    }

    #[test]
    fn parse_tcp_syn() {
        let p = tcp_packet(
            sa(192, 168, 137, 50, 40000),
            sa(93, 184, 216, 34, 443),
            tcp_flags::SYN,
            &[],
        );
        let info = parse(&p).unwrap();
        assert_eq!(info.proto, Proto::Tcp);
        assert_eq!(info.src, sa(192, 168, 137, 50, 40000));
        assert_eq!(info.dst, sa(93, 184, 216, 34, 443));
        assert!(info.is_syn());
        assert!(checksums_valid(&p, &info));
        assert_eq!(packet_len(&p), Some(40));
    }

    #[test]
    fn syn_ack_is_not_syn() {
        let p = tcp_packet(
            sa(10, 0, 0, 2, 1),
            sa(10, 0, 0, 3, 2),
            tcp_flags::SYN | tcp_flags::ACK,
            &[],
        );
        assert!(!parse(&p).unwrap().is_syn());
    }

    #[test]
    fn rewrite_dst_and_checksums_equal_fresh_packet() {
        let phone = sa(192, 168, 137, 50, 40000);
        let remote = sa(93, 184, 216, 34, 443);
        let proxy = sa(192, 168, 137, 1, 8229);
        let payload = b"GET / HTTP/1.1\r\nHost: example.org\r\n\r\n";

        let mut p = tcp_packet(phone, remote, tcp_flags::ACK | 0x08, payload);
        let info = parse(&p).unwrap();
        set_dst(&mut p, &info, proxy);
        // Sans recalcul, les sommes sont invalides.
        assert!(!checksums_valid(&p, &parse(&p).unwrap()));
        fix_checksums(&mut p, &info);

        let info2 = parse(&p).unwrap();
        assert_eq!(info2.dst, proxy);
        assert_eq!(info2.src, phone);
        assert!(checksums_valid(&p, &info2));
        // Identique à un paquet fabriqué directement avec ces adresses.
        assert_eq!(p, tcp_packet(phone, proxy, tcp_flags::ACK | 0x08, payload));
    }

    #[test]
    fn rewrite_src_for_reply_path() {
        let phone = sa(192, 168, 137, 50, 40000);
        let remote = sa(93, 184, 216, 34, 443);
        let proxy = sa(192, 168, 137, 1, 8229);
        // Réponse du proxy local au téléphone, à ré-attribuer à l'adresse d'origine.
        let mut p = tcp_packet(proxy, phone, tcp_flags::SYN | tcp_flags::ACK, &[]);
        let info = parse(&p).unwrap();
        set_src(&mut p, &info, remote);
        fix_checksums(&mut p, &info);
        let i2 = parse(&p).unwrap();
        assert_eq!((i2.src, i2.dst), (remote, phone));
        assert!(checksums_valid(&p, &i2));
        assert_eq!(
            p,
            tcp_packet(remote, phone, tcp_flags::SYN | tcp_flags::ACK, &[])
        );
    }

    #[test]
    fn parse_errors() {
        assert_eq!(parse(&[0x45, 0]), Err(ParseError::TooShort));
        let mut p = tcp_packet(sa(1, 1, 1, 1, 1), sa(2, 2, 2, 2, 2), 0, &[]);
        let mut v6 = p.clone();
        v6[0] = 0x65;
        assert_eq!(parse(&v6), Err(ParseError::NotIpv4));
        p[6] = 0x20; // MF
        assert_eq!(parse(&p), Err(ParseError::Fragment));
        p[6] = 0;
        p[7] = 8; // décalage non nul
        assert_eq!(parse(&p), Err(ParseError::Fragment));
        p[7] = 0;
        p[9] = 1; // ICMP
        assert_eq!(parse(&p), Err(ParseError::UnsupportedProtocol(1)));
        p[9] = PROTO_TCP;
        p[2..4].copy_from_slice(&200u16.to_be_bytes());
        assert_eq!(parse(&p), Err(ParseError::BadHeader));
    }

    #[test]
    fn packet_len_splits_a_batch() {
        let a = tcp_packet(sa(1, 1, 1, 1, 1), sa(2, 2, 2, 2, 2), 0, b"abc");
        let b = tcp_packet(sa(1, 1, 1, 1, 1), sa(2, 2, 2, 2, 2), 0, b"defghij");
        let batch = [a.clone(), b.clone()].concat();
        let la = packet_len(&batch).unwrap();
        assert_eq!(la, a.len());
        assert_eq!(packet_len(&batch[la..]), Some(b.len()));
        assert_eq!(packet_len(&batch[..la - 1]), None);
        assert_eq!(packet_len(&[]), None);
    }

    fn datagram(payload: &[u8]) -> UdpDatagram<'_> {
        UdpDatagram {
            src: sa(8, 8, 8, 8, 53),
            dst: sa(192, 168, 137, 50, 41000),
            ident: 0xBEEF,
            ttl: 64,
            payload,
        }
    }

    #[test]
    fn small_udp_datagram_is_a_single_valid_packet() {
        let payload = b"hello udp";
        let mut out = Vec::new();
        let n = append_udp_packets(&mut out, &datagram(payload), DEFAULT_MTU).unwrap();
        assert_eq!(n, 1);
        let info = parse(&out).unwrap();
        assert_eq!(info.proto, Proto::Udp);
        assert_eq!(info.src, sa(8, 8, 8, 8, 53));
        assert_eq!(info.dst, sa(192, 168, 137, 50, 41000));
        assert_eq!(info.total_len, 20 + 8 + payload.len());
        assert_eq!(info.udp_payload(&out), payload);
        assert_eq!(out[8], 64);
        assert_eq!(be16(&out, 4), 0xBEEF);
        assert!(checksums_valid(&out, &info));
        // Somme UDP identique à la référence naïve.
        let mut seg = out[20..].to_vec();
        seg[6..8].fill(0);
        let pseudo = [
            &[8u8, 8, 8, 8][..],
            &[192, 168, 137, 50],
            &[0, 17],
            &(seg.len() as u16).to_be_bytes(),
        ]
        .concat();
        assert_eq!(be16(&out, 26), naive_checksum(&[&pseudo, &seg]));
    }

    #[test]
    fn empty_udp_payload() {
        let mut out = Vec::new();
        assert_eq!(
            append_udp_packets(&mut out, &datagram(&[]), DEFAULT_MTU),
            Ok(1)
        );
        let info = parse(&out).unwrap();
        assert_eq!(info.total_len, 28);
        assert!(checksums_valid(&out, &info));
    }

    #[test]
    fn exact_mtu_boundary_is_not_fragmented() {
        let payload = vec![7u8; DEFAULT_MTU - 28];
        let mut out = Vec::new();
        assert_eq!(
            append_udp_packets(&mut out, &datagram(&payload), DEFAULT_MTU),
            Ok(1)
        );
        assert_eq!(out.len(), DEFAULT_MTU);
        let payload = vec![7u8; DEFAULT_MTU - 27];
        out.clear();
        assert_eq!(
            append_udp_packets(&mut out, &datagram(&payload), DEFAULT_MTU),
            Ok(2)
        );
    }

    /// Découpe un lot et ré-assemble les fragments ; renvoie le datagramme UDP reconstruit.
    fn reassemble(batch: &[u8], mtu: usize) -> Vec<u8> {
        let mut off = 0;
        let mut frags: Vec<(usize, bool, Vec<u8>)> = Vec::new();
        while off < batch.len() {
            let len = packet_len(&batch[off..]).expect("paquet valide");
            let p = &batch[off..off + len];
            assert!(len <= mtu, "fragment de {len} > mtu {mtu}");
            // Somme d'en-tête IPv4 valide.
            let mut s = Sum::default();
            s.add(&p[..20]);
            assert_eq!(s.folded(), 0xFFFF);
            let ff = be16(p, 6);
            assert_eq!(ff & 0x4000, 0, "DF ne doit pas être posé");
            assert_eq!(be16(p, 4), 0xBEEF);
            frags.push((
                usize::from(ff & 0x1FFF) * 8,
                ff & 0x2000 != 0,
                p[20..].to_vec(),
            ));
            off += len;
        }
        let mut data = Vec::new();
        for (i, (foff, more, body)) in frags.iter().enumerate() {
            assert_eq!(*foff, data.len(), "décalage contigu");
            assert_eq!(*more, i + 1 != frags.len(), "MF seulement hors dernier");
            if *more {
                assert_eq!(body.len() % 8, 0, "fragment intermédiaire multiple de 8");
            }
            data.extend_from_slice(body);
        }
        data
    }

    #[test]
    fn large_datagram_is_fragmented_and_reassembles() {
        for size in [1473usize, 1480, 2000, 4000, 9000, MAX_UDP_PAYLOAD] {
            let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let d = datagram(&payload);
            let mut out = Vec::new();
            let n = append_udp_packets(&mut out, &d, DEFAULT_MTU).unwrap();
            assert!(n >= 2, "taille {size}");
            let dgram = reassemble(&out, DEFAULT_MTU);
            assert_eq!(dgram.len(), 8 + size);
            assert_eq!(&dgram[8..], &payload[..]);
            assert_eq!(usize::from(be16(&dgram, 4)), 8 + size);
            // La somme UDP du datagramme reconstruit est valide.
            let mut s = pseudo_header_sum(*d.src.ip(), *d.dst.ip(), PROTO_UDP, dgram.len());
            s.add(&dgram);
            assert_eq!(s.folded(), 0xFFFF, "taille {size}");
            // Nombre de fragments attendu : ceil((8+size) / 1480).
            assert_eq!(n, (8 + size).div_ceil(1480));
        }
    }

    #[test]
    fn fragmentation_with_small_mtu() {
        let payload = vec![0xA5u8; 100];
        let mut out = Vec::new();
        let n = append_udp_packets(&mut out, &datagram(&payload), 76).unwrap();
        // chunk = (76-20)/8*8 = 56 ; (108 / 56) -> 2 fragments
        assert_eq!(n, 2);
        assert_eq!(reassemble(&out, 76).len(), 108);
    }

    #[test]
    fn build_errors() {
        let mut out = Vec::new();
        let big = vec![0u8; MAX_UDP_PAYLOAD + 1];
        assert_eq!(
            append_udp_packets(&mut out, &datagram(&big), DEFAULT_MTU),
            Err(BuildError::TooLarge(MAX_UDP_PAYLOAD + 1))
        );
        assert_eq!(
            append_udp_packets(&mut out, &datagram(b"x"), 40),
            Err(BuildError::BadMtu(40))
        );
        assert!(out.is_empty());
    }

    #[test]
    fn udp_rewrite_roundtrip() {
        let mut out = Vec::new();
        append_udp_packets(&mut out, &datagram(b"payload"), DEFAULT_MTU).unwrap();
        let info = parse(&out).unwrap();
        set_dst(&mut out, &info, sa(192, 168, 137, 1, 53));
        fix_checksums(&mut out, &info);
        let i2 = parse(&out).unwrap();
        assert_eq!(i2.dst, sa(192, 168, 137, 1, 53));
        assert!(checksums_valid(&out, &i2));
    }

    /// Recoupement avec l'implémentation officielle (`WinDivertHelperCalcChecksums`), qui
    /// ne requiert pas les droits administrateur. Ignoré si la DLL n'est pas vendorée.
    #[test]
    fn checksums_agree_with_windivert_helper() {
        let dll = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../vendor/windivert/WinDivert.dll");
        if !dll.exists() || !cfg!(windows) {
            eprintln!("WinDivert.dll absente : test ignoré");
            return;
        }
        let lib = crate::ffi::WinDivert::load(&dll).expect("chargement de la DLL");

        let phone = sa(192, 168, 137, 50, 40000);
        let remote = sa(93, 184, 216, 34, 443);
        let mut cases: Vec<Vec<u8>> = vec![
            tcp_packet(phone, remote, tcp_flags::SYN, &[]),
            tcp_packet(phone, remote, tcp_flags::ACK, b"odd"),
            tcp_packet(remote, phone, tcp_flags::ACK, &vec![0xFF; 1400]),
        ];
        let mut udp = Vec::new();
        append_udp_packets(&mut udp, &datagram(b"dns-ish payload!"), DEFAULT_MTU).unwrap();
        cases.push(udp);

        for ours in cases {
            let mut theirs = ours.clone();
            // Invalide les sommes puis laisse WinDivert les recalculer.
            theirs[10..12].fill(0);
            let info = parse(&ours).unwrap();
            let ck_off = info.ihl + if info.proto == Proto::Tcp { 16 } else { 6 };
            theirs[ck_off..ck_off + 2].fill(0);
            assert!(lib.calc_checksums(&mut theirs, None));
            assert_eq!(ours, theirs);
        }
    }
}
