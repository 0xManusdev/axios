//! FFI minimale vers `WinDivert.dll` 2.2 (chargement dynamique).
//!
//! Les signatures et la disposition de `WINDIVERT_ADDRESS` suivent l'en-tête officiel
//! `windivert.h` 2.2. Rien ici n'exige les droits administrateur tant qu'aucun handle n'est
//! ouvert (le chargement de la DLL et `WinDivertHelperCalcChecksums` sont purement
//! en espace utilisateur).

use std::ffi::{c_void, CString};
use std::io;
use std::path::Path;
use std::ptr;
use std::sync::Arc;

use libloading::Library;

use crate::error::EngineError;

/// `WINDIVERT_LAYER_NETWORK`.
pub const LAYER_NETWORK: u32 = 0;
/// `WINDIVERT_LAYER_NETWORK_FORWARD`.
pub const LAYER_NETWORK_FORWARD: u32 = 1;

/// `WINDIVERT_FLAG_SEND_ONLY` (alias `WRITE_ONLY`).
pub const FLAG_SEND_ONLY: u64 = 0x0008;

/// `WINDIVERT_SHUTDOWN_BOTH`.
const SHUTDOWN_BOTH: u32 = 3;

/// `WINDIVERT_EVENT_NETWORK_PACKET`.
const EVENT_NETWORK_PACKET: u8 = 0;

/// Nombre maximal de paquets par lot (`WINDIVERT_BATCH_MAX`).
pub const BATCH_MAX: usize = 255;

const BIT_OUTBOUND: u32 = 1 << 17;
const BIT_LOOPBACK: u32 = 1 << 18;
const BIT_IMPOSTOR: u32 = 1 << 19;
const BIT_IPV6: u32 = 1 << 20;

/// `WINDIVERT_ADDRESS` (80 octets).
///
/// Disposition C : `Timestamp` (8), un mot de champs de bits (`Layer:8`, `Event:8`, `Sniffed`,
/// `Outbound`, `Loopback`, `Impostor`, `IPv6`, `IPChecksum`, `TCPChecksum`, `UDPChecksum`,
/// `Reserved1:8`), `Reserved2` (4), puis une union de 64 octets dont la variante réseau
/// contient `IfIdx` et `SubIfIdx` (`u32` chacun).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address {
    timestamp: i64,
    flags: u32,
    reserved2: u32,
    union_data: [u8; 64],
}

impl Default for Address {
    fn default() -> Self {
        Self {
            timestamp: 0,
            flags: 0,
            reserved2: 0,
            union_data: [0; 64],
        }
    }
}

impl Address {
    /// Adresse pour injecter un paquet sur la couche NETWORK.
    pub fn network(if_idx: u32, sub_if_idx: u32, outbound: bool) -> Self {
        let mut a = Self {
            flags: LAYER_NETWORK | (u32::from(EVENT_NETWORK_PACKET) << 8),
            ..Self::default()
        };
        a.set_outbound(outbound);
        a.set_if_idx(if_idx);
        a.set_sub_if_idx(sub_if_idx);
        a
    }

    /// Couche (`WINDIVERT_LAYER_*`).
    pub fn layer(&self) -> u32 {
        self.flags & 0xFF
    }

    /// Événement (`WINDIVERT_EVENT_*`).
    pub fn event(&self) -> u8 {
        ((self.flags >> 8) & 0xFF) as u8
    }

    pub fn outbound(&self) -> bool {
        self.flags & BIT_OUTBOUND != 0
    }

    pub fn set_outbound(&mut self, outbound: bool) {
        self.set_bit(BIT_OUTBOUND, outbound);
    }

    pub fn loopback(&self) -> bool {
        self.flags & BIT_LOOPBACK != 0
    }

    pub fn impostor(&self) -> bool {
        self.flags & BIT_IMPOSTOR != 0
    }

    pub fn ipv6(&self) -> bool {
        self.flags & BIT_IPV6 != 0
    }

    /// `Network.IfIdx`.
    pub fn if_idx(&self) -> u32 {
        self.read_u32(0)
    }

    pub fn set_if_idx(&mut self, v: u32) {
        self.write_u32(0, v);
    }

    /// `Network.SubIfIdx`.
    pub fn sub_if_idx(&self) -> u32 {
        self.read_u32(4)
    }

    pub fn set_sub_if_idx(&mut self, v: u32) {
        self.write_u32(4, v);
    }

    fn set_bit(&mut self, bit: u32, on: bool) {
        if on {
            self.flags |= bit;
        } else {
            self.flags &= !bit;
        }
    }

    fn read_u32(&self, off: usize) -> u32 {
        let mut b = [0u8; 4];
        b.copy_from_slice(&self.union_data[off..off + 4]);
        u32::from_ne_bytes(b)
    }

    fn write_u32(&mut self, off: usize, v: u32) {
        self.union_data[off..off + 4].copy_from_slice(&v.to_ne_bytes());
    }
}

type OpenFn = unsafe extern "system" fn(*const u8, u32, i16, u64) -> *mut c_void;
type RecvExFn = unsafe extern "system" fn(
    *mut c_void,
    *mut c_void,
    u32,
    *mut u32,
    u64,
    *mut Address,
    *mut u32,
    *mut c_void,
) -> i32;
type SendExFn = unsafe extern "system" fn(
    *mut c_void,
    *const c_void,
    u32,
    *mut u32,
    u64,
    *const Address,
    u32,
    *mut c_void,
) -> i32;
type ShutdownFn = unsafe extern "system" fn(*mut c_void, u32) -> i32;
type CloseFn = unsafe extern "system" fn(*mut c_void) -> i32;
type CalcChecksumsFn = unsafe extern "system" fn(*mut c_void, u32, *mut Address, u64) -> i32;

/// Bibliothèque WinDivert chargée. Les pointeurs de fonction ne sont valables que tant que
/// `_lib` vit : la structure les possède ensemble.
pub struct WinDivert {
    open: OpenFn,
    recv_ex: RecvExFn,
    send_ex: SendExFn,
    shutdown: ShutdownFn,
    close: CloseFn,
    calc_checksums: CalcChecksumsFn,
    _lib: Library,
}

impl WinDivert {
    /// Charge `WinDivert.dll` depuis `path` (`WinDivert64.sys` doit être dans le même dossier).
    pub fn load(path: &Path) -> Result<Arc<Self>, EngineError> {
        // SAFETY : charger une DLL exécute son code d'initialisation ; WinDivert.dll est une
        // bibliothèque officielle dont l'initialisation n'a pas d'effet de bord notable.
        let lib = unsafe { Library::new(path) }.map_err(|source| EngineError::DllLoad {
            path: path.to_path_buf(),
            source,
        })?;

        macro_rules! sym {
            ($name:literal, $ty:ty) => {{
                // SAFETY : le type de fonction correspond à la signature de `windivert.h` 2.2.
                let s: libloading::Symbol<'_, $ty> = unsafe {
                    lib.get(concat!($name, "\0").as_bytes())
                }
                .map_err(|source| EngineError::Symbol {
                    name: $name,
                    source,
                })?;
                *s
            }};
        }

        let open = sym!("WinDivertOpen", OpenFn);
        let recv_ex = sym!("WinDivertRecvEx", RecvExFn);
        let send_ex = sym!("WinDivertSendEx", SendExFn);
        let shutdown = sym!("WinDivertShutdown", ShutdownFn);
        let close = sym!("WinDivertClose", CloseFn);
        let calc_checksums = sym!("WinDivertHelperCalcChecksums", CalcChecksumsFn);

        Ok(Arc::new(Self {
            open,
            recv_ex,
            send_ex,
            shutdown,
            close,
            calc_checksums,
            _lib: lib,
        }))
    }

    /// Ouvre un handle (`WinDivertOpen`). Nécessite les droits administrateur.
    pub fn open(
        self: &Arc<Self>,
        filter: &str,
        layer: u32,
        priority: i16,
        flags: u64,
    ) -> Result<Handle, EngineError> {
        let filter = CString::new(filter)
            .map_err(|_| EngineError::Config("filtre WinDivert invalide".into()))?;
        // SAFETY : `filter` est une chaîne C valide pour la durée de l'appel.
        let raw = unsafe { (self.open)(filter.as_ptr().cast(), layer, priority, flags) };
        if raw as isize == -1 || raw.is_null() {
            let code = io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32;
            return Err(EngineError::DriverOpen { code });
        }
        Ok(Handle {
            raw: raw as usize,
            lib: Arc::clone(self),
        })
    }

    /// Recalcule les sommes de contrôle d'un paquet (`WinDivertHelperCalcChecksums`).
    pub fn calc_checksums(&self, packet: &mut [u8], addr: Option<&mut Address>) -> bool {
        let addr_ptr = addr.map_or(ptr::null_mut(), |a| a as *mut Address);
        // SAFETY : tampon valide en écriture sur `packet.len()` octets.
        unsafe {
            (self.calc_checksums)(
                packet.as_mut_ptr().cast(),
                packet.len().min(u32::MAX as usize) as u32,
                addr_ptr,
                0,
            ) != 0
        }
    }
}

/// Handle WinDivert ouvert. Les opérations sont thread-safe côté pilote.
pub struct Handle {
    raw: usize,
    lib: Arc<WinDivert>,
}

/// Résultat d'une réception par lot.
#[derive(Clone, Copy, Debug)]
pub struct RecvBatch {
    /// Octets de paquets écrits dans le tampon (paquets contigus).
    pub bytes: usize,
    /// Nombre d'adresses (donc de paquets) écrites.
    pub count: usize,
}

impl Handle {
    fn raw_ptr(&self) -> *mut c_void {
        self.raw as *mut c_void
    }

    /// `WinDivertRecvEx` : bloque jusqu'à au moins un paquet, en lit jusqu'à `addrs.len()`.
    pub fn recv_batch(&self, buf: &mut [u8], addrs: &mut [Address]) -> io::Result<RecvBatch> {
        let mut recv_len = 0u32;
        let mut addr_len = std::mem::size_of_val(addrs).min(u32::MAX as usize) as u32;
        // SAFETY : les tampons sont valides en écriture pour les longueurs annoncées.
        let ok = unsafe {
            (self.lib.recv_ex)(
                self.raw_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len().min(u32::MAX as usize) as u32,
                &mut recv_len,
                0,
                addrs.as_mut_ptr(),
                &mut addr_len,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(RecvBatch {
            bytes: recv_len as usize,
            count: addr_len as usize / size_of::<Address>(),
        })
    }

    /// `WinDivertSendEx` : injecte `addrs.len()` paquets contigus dans `packets`.
    pub fn send_batch(&self, packets: &[u8], addrs: &[Address]) -> io::Result<()> {
        let mut sent = 0u32;
        // SAFETY : les tampons sont valides en lecture pour les longueurs annoncées.
        let ok = unsafe {
            (self.lib.send_ex)(
                self.raw_ptr(),
                packets.as_ptr().cast(),
                packets.len().min(u32::MAX as usize) as u32,
                &mut sent,
                0,
                addrs.as_ptr(),
                std::mem::size_of_val(addrs).min(u32::MAX as usize) as u32,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// `WinDivertShutdown(BOTH)` : débloque les `recv` en attente. Idempotent.
    pub fn shutdown(&self) {
        // SAFETY : handle valide tant que `self` existe.
        unsafe {
            (self.lib.shutdown)(self.raw_ptr(), SHUTDOWN_BOTH);
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY : handle ouvert par `WinDivert::open`, fermé une seule fois ici.
        unsafe {
            (self.lib.close)(self.raw_ptr());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, offset_of};

    #[test]
    fn address_layout_matches_windivert_h() {
        assert_eq!(size_of::<Address>(), 80);
        assert_eq!(align_of::<Address>(), 8);
        assert_eq!(offset_of!(Address, flags), 8);
        assert_eq!(offset_of!(Address, reserved2), 12);
        assert_eq!(offset_of!(Address, union_data), 16);
    }

    #[test]
    fn address_bitfields() {
        let a = Address::network(17, 3, true);
        assert_eq!(a.layer(), LAYER_NETWORK);
        assert_eq!(a.event(), 0);
        assert!(a.outbound());
        assert!(!a.loopback() && !a.impostor() && !a.ipv6());
        assert_eq!(a.if_idx(), 17);
        assert_eq!(a.sub_if_idx(), 3);
        // Outbound est le bit 17 du mot de champs de bits.
        assert_eq!(a.flags & (1 << 17), 1 << 17);

        let mut b = Address::network(5, 0, false);
        assert!(!b.outbound());
        b.set_outbound(true);
        b.set_if_idx(9);
        assert!(b.outbound());
        assert_eq!(b.if_idx(), 9);
        assert_eq!(b.sub_if_idx(), 0);
        b.set_outbound(false);
        assert!(!b.outbound());
    }

    #[test]
    fn network_union_is_at_offset_16() {
        let a = Address::network(0x0102_0304, 0x0506_0708, false);
        // SAFETY : `Address` est `repr(C)` sans padding (8 + 4 + 4 + 64 = 80).
        let bytes: [u8; 80] = unsafe { std::mem::transmute(a) };
        assert_eq!(&bytes[16..20], &0x0102_0304u32.to_ne_bytes());
        assert_eq!(&bytes[20..24], &0x0506_0708u32.to_ne_bytes());
    }
}
