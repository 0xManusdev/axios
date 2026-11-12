//! Moteur NAT utilisateur (WinDivert). Voir CONTRACT.md.
//!
//! Le routeur amont force le TTL à 1 : Windows ne peut pas relayer les paquets du téléphone.
//! On les intercepte donc avant le routage (couche `NETWORK_FORWARD`) et c'est le PC qui ouvre
//! lui-même les connexions : proxy TCP transparent local, sockets UDP par session.
//!
//! Modules :
//! - [`ffi`] : liaison dynamique minimale vers `WinDivert.dll` 2.2 ;
//! - [`packet`] : IPv4/TCP/UDP en Rust pur (analyse, réécriture, sommes, fragmentation) ;
//! - [`subnet`] : réseau du point d'accès et filtres WinDivert ;
//! - [`nat`] : table NAT TCP ; [`udp`] : sessions UDP ; [`tcp_proxy`] : proxy TCP ;
//! - [`policy`] : politique par appareil (blocage, débit, isolation, DNS) ;
//! - [`ratelimit`] : seaux à jetons ; [`dns`] : analyse DNS ; `dns_proxy` : interception DNS ;
//! - [`stats`] : compteurs ; [`shared`] : état partagé ; `engine` : orchestration.

pub mod dns;
mod dns_proxy;
mod engine;
mod error;
pub mod ffi;
#[doc(hidden)]
pub mod nat;
pub mod packet;
pub mod policy;
#[doc(hidden)]
pub mod ratelimit;
#[doc(hidden)]
pub mod shared;
pub mod stats;
pub mod subnet;
#[doc(hidden)]
pub mod tcp_proxy;
#[doc(hidden)]
pub mod udp;

pub use engine::{Engine, EngineConfig};
pub use error::EngineError;
pub use policy::{Blocklist, DnsPolicy, Policy};
pub use stats::{Counters, EngineStats, PacketCounters};
