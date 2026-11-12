//! Table NAT TCP : (IP, port) du téléphone -> destination d'origine visée.
//!
//! Cycle de vie d'une entrée :
//! `Pending` (SYN vu) -> `Active` (le proxy a accepté la connexion) -> `Closed` (fin de la
//! connexion). Une entrée `Closed` reste [`CLOSED_LINGER`] pour que les derniers FIN/ACK
//! soient encore réécrits ; une entrée `Pending` jamais acceptée expire après
//! [`PENDING_TTL`].

use std::net::SocketAddrV4;
use std::time::{Duration, Instant};

use dashmap::DashMap;

use crate::packet::{self, PacketInfo, Proto};

/// Durée de rétention d'une entrée après la fin de la connexion.
pub const CLOSED_LINGER: Duration = Duration::from_secs(60);
/// Durée de vie d'une entrée dont la connexion n'a jamais été acceptée par le proxy.
pub const PENDING_TTL: Duration = Duration::from_secs(120);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Pending { since: Instant },
    Active,
    Closed { at: Instant },
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    dst: SocketAddrV4,
    generation: u64,
    state: State,
}

/// Jeton identifiant une entrée précise (évite qu'une vieille connexion ne supprime l'entrée
/// d'une connexion plus récente réutilisant le même port source).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Claim {
    pub dst: SocketAddrV4,
    generation: u64,
}

#[derive(Default)]
pub struct TcpNat {
    map: DashMap<SocketAddrV4, Entry>,
    next_generation: std::sync::atomic::AtomicU64,
}

impl TcpNat {
    pub fn new() -> Self {
        Self::default()
    }

    /// Enregistre un SYN du téléphone `client` vers `dst`. Une retransmission du même SYN
    /// pendant l'établissement ne change rien ; sinon une nouvelle entrée remplace l'ancienne.
    pub fn register_syn(&self, client: SocketAddrV4, dst: SocketAddrV4, now: Instant) {
        use dashmap::mapref::entry::Entry as MapEntry;
        let fresh = |this: &Self| Entry {
            dst,
            generation: this
                .next_generation
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            state: State::Pending { since: now },
        };
        match self.map.entry(client) {
            MapEntry::Vacant(v) => {
                v.insert(fresh(self));
            }
            MapEntry::Occupied(mut o) => {
                let cur = *o.get();
                let same_live = cur.dst == dst && !matches!(cur.state, State::Closed { .. });
                if !same_live {
                    o.insert(fresh(self));
                }
            }
        }
    }

    /// Destination d'origine du téléphone `client`, si une entrée existe.
    pub fn lookup(&self, client: SocketAddrV4) -> Option<SocketAddrV4> {
        self.map.get(&client).map(|e| e.dst)
    }

    /// Appelé par le proxy à l'acceptation : marque l'entrée active et renvoie un jeton.
    pub fn claim(&self, client: SocketAddrV4) -> Option<Claim> {
        let mut e = self.map.get_mut(&client)?;
        if matches!(e.state, State::Closed { .. }) {
            return None;
        }
        e.state = State::Active;
        Some(Claim {
            dst: e.dst,
            generation: e.generation,
        })
    }

    /// Marque la connexion terminée ; l'entrée sera supprimée par [`TcpNat::sweep`] après
    /// [`CLOSED_LINGER`]. Sans effet si l'entrée a été remplacée entre-temps.
    pub fn close(&self, client: SocketAddrV4, claim: Claim, now: Instant) {
        if let Some(mut e) = self.map.get_mut(&client) {
            if e.generation == claim.generation {
                e.state = State::Closed { at: now };
            }
        }
    }

    /// Supprime les entrées expirées.
    pub fn sweep(&self, now: Instant) {
        self.map.retain(|_, e| match e.state {
            State::Pending { since } => now.saturating_duration_since(since) < PENDING_TTL,
            State::Active => true,
            State::Closed { at } => now.saturating_duration_since(at) < CLOSED_LINGER,
        });
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Téléphone -> proxy local. Sur SYN, enregistre la destination d'origine ; un paquet
    /// sans entrée est ignoré (`false`). Sinon copie le paquet à la fin de `out`, destination
    /// remplacée par `proxy` et sommes de contrôle recalculées (`true`).
    pub fn rewrite_to_proxy(
        &self,
        pkt: &[u8],
        info: &PacketInfo,
        proxy: SocketAddrV4,
        out: &mut Vec<u8>,
        now: Instant,
    ) -> bool {
        if info.proto != Proto::Tcp {
            return false;
        }
        if info.is_syn() {
            self.register_syn(info.src, info.dst, now);
        } else if self.lookup(info.src).is_none() {
            return false;
        }
        let start = out.len();
        out.extend_from_slice(&pkt[..info.total_len]);
        let copy = &mut out[start..];
        packet::set_dst(copy, info, proxy);
        packet::fix_checksums(copy, info);
        true
    }

    /// Proxy local -> téléphone. Remplace la source par la destination d'origine visée par
    /// le téléphone ; sans entrée, le paquet est jeté (`false`).
    pub fn rewrite_from_proxy(&self, pkt: &[u8], info: &PacketInfo, out: &mut Vec<u8>) -> bool {
        if info.proto != Proto::Tcp {
            return false;
        }
        let Some(orig) = self.lookup(info.dst) else {
            return false;
        };
        let start = out.len();
        out.extend_from_slice(&pkt[..info.total_len]);
        let copy = &mut out[start..];
        packet::set_src(copy, info, orig);
        packet::fix_checksums(copy, info);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::tests::sa;

    fn t0() -> Instant {
        Instant::now()
    }

    #[test]
    fn register_then_lookup() {
        let nat = TcpNat::new();
        let c = sa(192, 168, 137, 50, 40000);
        let d = sa(93, 184, 216, 34, 443);
        assert_eq!(nat.lookup(c), None);
        nat.register_syn(c, d, t0());
        assert_eq!(nat.lookup(c), Some(d));
        assert_eq!(nat.lookup(sa(192, 168, 137, 50, 40001)), None);
    }

    #[test]
    fn syn_retransmission_keeps_entry_but_new_dest_replaces() {
        let nat = TcpNat::new();
        let c = sa(192, 168, 137, 50, 40000);
        let d1 = sa(93, 184, 216, 34, 443);
        let d2 = sa(1, 1, 1, 1, 80);
        nat.register_syn(c, d1, t0());
        let claim = nat.claim(c).unwrap();
        nat.register_syn(c, d1, t0()); // retransmission : conservée
        nat.close(c, claim, t0());
        assert_eq!(nat.lookup(c), Some(d1));
        nat.register_syn(c, d2, t0());
        assert_eq!(nat.lookup(c), Some(d2));
    }

    #[test]
    fn closed_entry_lingers_then_is_swept() {
        let nat = TcpNat::new();
        let c = sa(192, 168, 137, 50, 40000);
        let start = t0();
        nat.register_syn(c, sa(8, 8, 8, 8, 443), start);
        let claim = nat.claim(c).unwrap();
        nat.sweep(start + Duration::from_secs(10_000)); // Active : jamais balayée
        assert_eq!(nat.len(), 1);
        nat.close(c, claim, start);
        nat.sweep(start + CLOSED_LINGER - Duration::from_secs(1));
        assert_eq!(nat.len(), 1, "encore nécessaire pour les derniers FIN/ACK");
        nat.sweep(start + CLOSED_LINGER);
        assert!(nat.is_empty());
    }

    #[test]
    fn stale_close_does_not_remove_newer_connection() {
        let nat = TcpNat::new();
        let c = sa(192, 168, 137, 50, 40000);
        let start = t0();
        nat.register_syn(c, sa(8, 8, 8, 8, 443), start);
        let old = nat.claim(c).unwrap();
        nat.close(c, old, start);
        // Même port source réutilisé pour une autre destination.
        nat.register_syn(c, sa(9, 9, 9, 9, 443), start);
        let new = nat.claim(c).unwrap();
        assert_ne!(old, new);
        nat.close(c, old, start); // fermeture tardive de l'ancienne : ignorée
        nat.sweep(start + CLOSED_LINGER * 2);
        assert_eq!(nat.lookup(c), Some(sa(9, 9, 9, 9, 443)));
    }

    #[test]
    fn pending_entries_expire() {
        let nat = TcpNat::new();
        let start = t0();
        nat.register_syn(sa(192, 168, 137, 50, 1), sa(8, 8, 8, 8, 443), start);
        nat.sweep(start + PENDING_TTL - Duration::from_secs(1));
        assert_eq!(nat.len(), 1);
        nat.sweep(start + PENDING_TTL);
        assert!(nat.is_empty());
    }

    #[test]
    fn full_tcp_flow_rewrites_both_directions() {
        use crate::packet::{checksums_valid, parse, tcp_flags, tests::tcp_packet};
        let nat = TcpNat::new();
        let phone = sa(192, 168, 137, 50, 40000);
        let remote = sa(93, 184, 216, 34, 443);
        let proxy = sa(192, 168, 137, 1, 8229);
        let mut out = Vec::new();

        // ACK sans SYN préalable : ignoré.
        let ack = tcp_packet(phone, remote, tcp_flags::ACK, b"x");
        assert!(!nat.rewrite_to_proxy(&ack, &parse(&ack).unwrap(), proxy, &mut out, t0()));
        assert!(out.is_empty());

        // SYN : enregistré et réécrit vers le proxy.
        let syn = tcp_packet(phone, remote, tcp_flags::SYN, &[]);
        assert!(nat.rewrite_to_proxy(&syn, &parse(&syn).unwrap(), proxy, &mut out, t0()));
        assert_eq!(out, tcp_packet(phone, proxy, tcp_flags::SYN, &[]));
        out.clear();

        // Données suivantes : acceptées maintenant, destination = proxy, sommes valides.
        assert!(nat.rewrite_to_proxy(&ack, &parse(&ack).unwrap(), proxy, &mut out, t0()));
        let i = parse(&out).unwrap();
        assert_eq!((i.src, i.dst), (phone, proxy));
        assert!(checksums_valid(&out, &i));
        out.clear();

        // Réponse du proxy : la source redevient l'adresse d'origine.
        let reply = tcp_packet(proxy, phone, tcp_flags::SYN | tcp_flags::ACK, &[]);
        assert!(nat.rewrite_from_proxy(&reply, &parse(&reply).unwrap(), &mut out));
        assert_eq!(
            out,
            tcp_packet(remote, phone, tcp_flags::SYN | tcp_flags::ACK, &[])
        );
        out.clear();

        // Réponse vers un téléphone inconnu : jetée.
        let stray = tcp_packet(proxy, sa(192, 168, 137, 99, 1), tcp_flags::ACK, &[]);
        assert!(!nat.rewrite_from_proxy(&stray, &parse(&stray).unwrap(), &mut out));
        assert!(out.is_empty());
    }

    #[test]
    fn closed_entry_cannot_be_claimed_again() {
        let nat = TcpNat::new();
        let c = sa(192, 168, 137, 50, 40000);
        nat.register_syn(c, sa(8, 8, 8, 8, 443), t0());
        let claim = nat.claim(c).unwrap();
        nat.close(c, claim, t0());
        assert!(nat.claim(c).is_none());
    }
}
