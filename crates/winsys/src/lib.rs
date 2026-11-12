//! Intégrations système Windows de Partage Wi-Fi. Voir CONTRACT.md et CONTRACT-V2.md.
//!
//! Toutes les fonctions sont bloquantes et utilisables depuis n'importe quel thread.

pub mod autostart;
mod com;
pub mod elevation;
mod error;
pub mod firewall;
pub mod hotspot;
pub mod mac;
pub mod net;
mod oui;
pub mod sync;
mod wlan;

pub use error::{Result, WinsysError};
