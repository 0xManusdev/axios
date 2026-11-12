# Partage Wi-Fi (Rust) — contrat d'architecture

Source de vérité pour tous les contributeurs. Ne pas modifier une interface publique
décrite ici sans le signaler explicitement dans son rapport final.

## Problème résolu

Le routeur amont (MikroTik) force le TTL de **tous** les paquets envoyés aux clients à 1.
Le PC reçoit ces paquets (il en est la destination), mais Windows ne peut pas les relayer
au téléphone via le point d'accès (ICS) : TTL 1 → 0 au routage → paquet jeté.

Solution validée (prototype Python : `D:\codes\my_projects\partage-wifi\partage_wifi.pyw`,
testé avec un vrai téléphone : TCP + UDP OK, 0 erreur) : **NAT en espace utilisateur**.
On intercepte les paquets du téléphone avant que Windows ne les relaie, et c'est le PC
qui ouvre lui-même les connexions. Rien n'est routé, le TTL n'a plus d'importance.
Aucun réglage côté téléphone.

## Arborescence et propriété

```
partage-wifi-rs/
  Cargo.toml            workspace (members: crates/engine, crates/winsys, crates/support, crates/auto, app/src-tauri)
  CONTRACT.md           ce fichier
  vendor/windivert/     WinDivert.dll + WinDivert64.sys (binaires officiels 2.2.x, fournis par l'intégrateur)
  crates/engine/        pw-engine  — moteur NAT (agent "engine")
  crates/winsys/        pw-winsys  — intégrations Windows (agent "winsys")
  crates/support/       pw-support — journal, emplacements, WinDivert embarqué (communs)
  crates/auto/          partage-wifi-auto — partage automatique sans interface (§4)
  app/                  interface web : index.html, src/**, package.json, vite, tsconfig (agent "ui")
  app/src-tauri/        coquille Tauri 2 : Rust, tauri.conf.json, capabilities, icônes, build.rs (agent "shell")
```

Chaque agent n'écrit **que** dans son périmètre. Compilation avec un dossier cible dédié
pour ne pas se bloquer mutuellement : `CARGO_TARGET_DIR=target/<agent>`
(ex. `cargo test -p pw-engine` avec `CARGO_TARGET_DIR=target/engine`).

Environnement : Windows 11, Rust stable MSVC (`%USERPROFILE%\.cargo\bin`), Node 24 / npm.
L'app tourne **toujours en administrateur** (manifeste `requireAdministrator`).

Qualité attendue : code idiomatique, `cargo clippy -- -D warnings` propre, `cargo fmt`,
pas de `unwrap()` hors tests / invariants documentés, erreurs typées (`thiserror`),
logs via la crate `log`, tests unitaires sur la logique pure. Messages d'erreur
destinés à l'utilisateur **en français**, courts.

---

## 1. `pw-engine` (crates/engine)

### API publique

```rust
pub struct EngineConfig {
    pub gateway: std::net::Ipv4Addr,   // IP du PC côté point d'accès (ICS), ex. 192.168.137.1
    pub prefix_len: u8,                 // 24
    pub tcp_port: u16,                  // port du proxy TCP transparent local, ex. 8229
    pub windivert_dll: std::path::PathBuf, // chemin de WinDivert.dll (WinDivert64.sys dans le même dossier)
}

pub struct Engine { /* … */ }

impl Engine {
    /// Ouvre les handles WinDivert, lance les threads / runtime. N'échoue pas si le
    /// point d'accès est éteint : le moteur reste au repos tant qu'aucun paquet ne passe.
    pub fn start(cfg: EngineConfig) -> Result<Engine, EngineError>;
    /// Index de l'interface du point d'accès (fourni par l'app quand le point d'accès démarre ;
    /// None quand il s'arrête). Tant que None, les paquets interceptés sont ignorés.
    pub fn set_hotspot_interface(&self, if_index: Option<u32>);
    /// Instantané des compteurs (non bloquant, bon marché : appelé chaque seconde).
    pub fn stats(&self) -> EngineStats;
    /// Arrêt propre (WinDivertShutdown, fermeture des sockets, join des threads). Drop l'appelle aussi.
    pub fn shutdown(self);
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters { pub up_bytes: u64, pub down_bytes: u64 } // up = téléphone→internet

#[derive(Clone, Debug, Default)]
pub struct EngineStats {
    pub total: Counters,
    pub per_device: std::collections::HashMap<std::net::Ipv4Addr, Counters>, // clé = IP du client
    pub active_tcp: usize,
    pub active_udp: usize,
    pub packets: PacketCounters,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PacketCounters { pub fwd_tcp: u64, pub fwd_udp: u64, pub reflected_out: u64, pub udp_back: u64, pub dropped: u64, pub errors: u64 }

#[derive(Debug, thiserror::Error)]
pub enum EngineError { /* DllLoad, DriverOpen { code: u32 }, Bind(std::io::Error), … — Display en français */ }
```

### Algorithme (identique au prototype Python, à reprendre fidèlement)

Réseau du point d'accès `N = gateway/prefix_len`.

1. **Handle FORWARD** (`WINDIVERT_LAYER_NETWORK_FORWARD`), filtre :
   `ip and (tcp or udp) and ip.SrcAddr >= N[2] and ip.SrcAddr <= N[-2] and (ip.DstAddr < N[0] or ip.DstAddr > N[-1]) and ip.DstAddr < 224.0.0.0`
   → paquets téléphone → internet. Ils ne sont **jamais** réinjectés tels quels.
   - **TCP** : sur SYN (sans ACK), enregistrer `nat[(src_ip, src_port)] = (dst_ip, dst_port)`.
     Paquet non-SYN sans entrée : ignorer. Sinon réécrire `dst = gateway:tcp_port`,
     recalculer les checksums, **réinjecter en INBOUND sur la couche NETWORK** avec
     `IfIdx = interface du point d'accès`, `SubIfIdx = 0`. La pile locale le livre au proxy.
   - **UDP** : une session par `(src_ip, src_port)` du téléphone = un socket UDP local
     (`0.0.0.0:0`), mapping indépendant de la destination (STUN / appels OK) :
     `sendto(payload, (dst_ip, dst_port))`. Expiration après 180 s d'inactivité.
2. **Handle OUT** (couche NETWORK), filtre :
   `outbound and tcp and ip.SrcAddr == gateway and tcp.SrcPort == tcp_port`
   → réponses du proxy local vers le téléphone : remplacer la source par `nat[(dst_ip, dst_port)]`
   (l'adresse d'origine visée par le téléphone), checksums, réinjecter en outbound. Sans entrée : jeter.
3. **Handle d'injection** (couche NETWORK, filtre `false`, `WINDIVERT_FLAG_SEND_ONLY`).
4. **Proxy TCP transparent** (tokio) écoutant `0.0.0.0:tcp_port` : à l'acceptation du pair
   `(ip, port)`, refuser si `ip ∉ N` ou pas d'entrée NAT ; sinon se connecter à la destination
   d'origine (timeout 15 s, happy-eyeballs non nécessaire : IPv4) et relayer dans les deux sens
   avec demi-fermeture (shutdown write), comptage d'octets par appareil. Retirer l'entrée NAT
   60 s après la fin de la connexion (les derniers FIN/ACK doivent encore être réécrits).
5. **Réponses UDP** : pour chaque datagramme reçu sur le socket d'une session depuis `(rip, rport)`,
   fabriquer un paquet IPv4/UDP `rip:rport → tel_ip:tel_port` (TTL 64, ID incrémental) et l'injecter
   en **outbound** sur l'interface du point d'accès. Si le datagramme dépasse le MTU (1500),
   **fragmenter en IPv4** proprement (le prototype les jetait — à corriger).
6. DNS : le téléphone utilise `gateway:53` (proxy DNS d'ICS) → local, non intercepté. Ne rien faire.

### Notes d'implémentation

- Charger WinDivert dynamiquement (`libloading`) depuis `windivert_dll` avec une FFI minimale
  vérifiée contre l'en-tête officiel `windivert.h` 2.2 : `WinDivertOpen`, `WinDivertRecvEx`,
  `WinDivertSendEx`, `WinDivertShutdown`, `WinDivertClose`, `WinDivertHelperCalcChecksums`.
  Attention à la disposition exacte de `WINDIVERT_ADDRESS` (80 octets, champs de bits) :
  ajouter un test `size_of == 80`. Doc : https://reqrypt.org/windivert-doc.html
- Réception par lots (`WinDivertRecvEx` avec plusieurs paquets) recommandée pour le débit.
- Parsing / réécriture d'en-têtes IPv4/TCP/UDP en Rust pur, testé unitairement
  (réécriture, checksum, fabrication UDP, fragmentation). Le checksum peut passer par
  `WinDivertHelperCalcChecksums` à l'exécution, mais garder une implémentation pure testable.
- Threads de réception bloquants + runtime tokio dédié (multi-thread) pour TCP/UDP.
- La table NAT est partagée entre threads : structure concurrente simple et correcte
  (`parking_lot::Mutex<HashMap>` ou `dashmap`), pas d'optimisation prématurée.
- Test d'intégration nécessitant admin + point d'accès : `#[ignore]`.

---

## 2. `pw-winsys` (crates/winsys)

Toutes les fonctions sont **bloquantes** : l'app les appelle depuis `spawn_blocking`.
Elles doivent fonctionner depuis n'importe quel thread (initialiser l'apartment COM/WinRT
en MTA si nécessaire). Crate `windows` (WinRT + Win32). Erreur : `WinsysError` (thiserror, Display en français).

```rust
pub mod hotspot {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    #[serde(rename_all = "lowercase")]
    pub enum Band { Auto, Ghz2_4, Ghz5, Ghz6 }  // sérialisé "auto" | "2.4" | "5" | "6" (renommer explicitement)

    #[derive(Clone, Debug, serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct HotspotInfo { pub on: bool, pub ssid: String, pub passphrase: String, pub band: Band, pub client_count: u32, pub max_clients: u32 }

    #[derive(Clone, Debug, serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct HotspotClient { pub mac: String /* "AA:BB:CC:DD:EE:FF" */, pub host_names: Vec<String> }

    pub fn info() -> Result<HotspotInfo, WinsysError>;
    pub fn start() -> Result<HotspotInfo, WinsysError>;
    pub fn stop() -> Result<HotspotInfo, WinsysError>;
    /// Valide (SSID 1–32 octets UTF-8, mot de passe 8–63 ASCII imprimables) puis applique.
    /// Si le point d'accès est actif, l'arrête, configure et le redémarre.
    pub fn configure(ssid: &str, passphrase: &str, band: Option<Band>) -> Result<HotspotInfo, WinsysError>;
    pub fn clients() -> Result<Vec<HotspotClient>, WinsysError>;
    /// Empêche Windows de couper le point d'accès quand aucun appareil n'est connecté
    /// (NetworkOperatorTetheringManager::DisableNoConnectionsTimeout[Async]). Best effort.
    pub fn set_keep_alive(enabled: bool) -> Result<(), WinsysError>;
}

pub mod net {
    /// IP du PC côté point d'accès : registre HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\ScopeAddress, défaut 192.168.137.1.
    pub fn ics_gateway() -> std::net::Ipv4Addr;
    /// Index de l'interface qui porte cette IPv4 (GetUnicastIpAddressTable / GetAdaptersAddresses).
    pub fn interface_index_for(ip: std::net::Ipv4Addr) -> Option<u32>;
    /// Voisins ARP résolus sur l'interface : (ip, "AA:BB:CC:DD:EE:FF") via GetIpNetTable2.
    pub fn neighbors(if_index: u32) -> Vec<(std::net::Ipv4Addr, String)>;
}

pub mod firewall {
    /// Crée ou remplace une règle entrante autorisant TCP `port` depuis `remote` (ex. "192.168.137.0/24")
    /// pour `program`, tous profils. Idempotent. API COM INetFwPolicy2 (pas de netsh).
    pub fn ensure_rule(name: &str, program: &std::path::Path, port: u16, remote: &str) -> Result<(), WinsysError>;
    pub fn remove_rule(name: &str) -> Result<(), WinsysError>;
}

pub mod autostart {
    /// Tâche planifiée « à l'ouverture de session », niveau d'exécution le plus élevé (pas d'UAC au démarrage),
    /// sans condition batterie. API COM ITaskService (pas de schtasks).
    pub fn is_enabled(task_name: &str) -> bool;
    pub fn set(task_name: &str, enabled: bool, exe: &std::path::Path, args: &str) -> Result<(), WinsysError>;
}

pub mod elevation { pub fn is_elevated() -> bool; }
```

Référence fonctionnelle du point d'accès (PowerShell / WinRT, validé sur cette machine) :
`NetworkInformation::GetInternetConnectionProfile()` → `NetworkOperatorTetheringManager::CreateFromConnectionProfile(profile)`
→ `StartTetheringAsync()`, `StopTetheringAsync()`, `TetheringOperationalState`, `ClientCount`,
`MaxClientCount`, `GetCurrentAccessPointConfiguration()` (Ssid, Passphrase, Band),
`ConfigureAccessPointAsync(cfg)`, `GetTetheringClients()` (MacAddress, HostNames).
Pas de profil internet → erreur « Aucune connexion internet ». Un résultat d'opération ≠ Success
→ erreur avec `AdditionalErrorMessage`.

---

## 3. Contrat app ↔ interface (Tauri 2, invoke + événements)

JSON en camelCase. Toutes les commandes renvoient `Result<T, String>` (message d'erreur
français prêt à afficher).

```ts
type Status = "off" | "starting" | "on" | "stopping" | "error";
type Band = "auto" | "2.4" | "5" | "6";

interface Snapshot {
  status: Status;
  ssid: string;
  passphrase: string;
  band: Band;
  maxClients: number;
  supportedBands: Band[];    // bandes acceptées par la carte Wi-Fi ("auto" toujours présent)
  error: string | null;      // message français, null si tout va bien
  engineReady: boolean;      // pilote réseau chargé
}

interface Device {
  id: string;                // MAC si connue, sinon IP
  name: string;              // nom d'hôte, sinon "" (l'UI affiche un libellé par défaut)
  ip: string | null;
  mac: string | null;
  rateDown: number;          // octets/s internet → appareil
  rateUp: number;            // octets/s appareil → internet
  totalDown: number;         // octets depuis le lancement de l'app
  totalUp: number;
}

interface Stats {
  rateDown: number; rateUp: number;   // total, octets/s (lissé sur ~2 s)
  totalDown: number; totalUp: number; // depuis le lancement
  devices: Device[];                  // appareils connectés (union clients WinRT + IP vues par le moteur)
}

interface Settings { autostart: boolean }
```

Commandes (`invoke`) :

| commande | arguments | retour |
|---|---|---|
| `get_snapshot` | — | `Snapshot` |
| `set_sharing` | `{ on: boolean }` | `Snapshot` |
| `configure_network` | `{ ssid: string, passphrase: string, band: Band }` | `Snapshot` |
| `get_settings` | — | `Settings` |
| `set_autostart` | `{ enabled: boolean }` | `Settings` |
| `quit_app` | — | `void` (arrête le point d'accès puis quitte) |

Événements (`listen`) :
- `snapshot` → `Snapshot` à chaque changement d'état (y compris changement externe, détecté par sondage toutes les 3 s).
- `stats` → `Stats` chaque seconde (même point d'accès arrêté : listes vides, débits 0).

Fenêtre : 420×720 logiques, non redimensionnable, **sans décorations** (`decorations: false`,
`shadow: true`, coins arrondis Windows 11 conservés), centrée. L'UI dessine sa propre barre de titre
(`data-tauri-drag-region`) avec boutons Réduire et Fermer. **Fermer = masquer dans la zone de notification**
(`getCurrentWindow().hide()`), quitter se fait via le menu de l'icône ou `quit_app`.
Permissions nécessaires dans les capabilities : `core:default`, `core:window:allow-start-dragging`,
`core:window:allow-minimize`, `core:window:allow-hide`, `core:window:allow-show`, `core:window:allow-set-focus`.

Lancé avec `--minimized` (démarrage automatique) : fenêtre cachée, seule l'icône de notification apparaît,
et le partage démarre automatiquement.

Icône de notification : clic gauche = afficher la fenêtre ; menu : « Ouvrir », « Activer le partage » /
« Désactiver le partage », « Quitter ». Instance unique (`tauri-plugin-single-instance` : relancer = montrer la fenêtre).

Fichiers de l'app : `%LOCALAPPDATA%\PartageWiFi\` — `windivert\` (binaires extraits de l'exe au premier
lancement / si différents), `logs\partage-wifi.log` (rotation simple).
Règle pare-feu : nom `PartageWiFi`, programme = exe courant, port TCP 8229, distant = réseau du point d'accès.
Tâche planifiée : `PartageWiFi`, arguments `--minimized`.

## 4. Briques communes et partage automatique

`pw-support` (crates/support) : emplacements (`paths`), journal à rotation (`logging::init(fichier, libellé)`),
WinDivert embarqué (`windivert::ensure_extracted`), relevé du trafic (`activity`), constantes `TCP_PORT`,
`PREFIX_LEN`, `ENGINE_LOCK` et `subnet_cidr`. Utilisé par l'app et par le partage automatique.

`pw-winsys::sync` : `NamedLock` (verrou entre processus, libéré à la fin du processus) et `NamedEvent` (signal).

**Un seul moteur à la fois** : le processus qui fait tourner le moteur tient `Global\PartageWiFi.Moteur`.
L'app le prend à son lancement (sinon erreur « Le partage automatique est actif… ») ; le partage
automatique le prend quand le point d'accès s'allume et le rend quand il s'éteint.

`partage-wifi-auto` (crates/auto, `partage-wifi-auto.exe`, sans fenêtre, manifeste administrateur) :
- double-clic : si aucune instance ne tourne, copie l'exe dans `%LOCALAPPDATA%\PartageWiFi\auto\`,
  enregistre la tâche `PartageWiFi-Auto` (ouverture de session, `--arriere-plan`) et la lance ;
  sinon propose de désactiver (tâche supprimée, signal `Global\PartageWiFi.Auto.Arret`, règle pare-feu
  et copie supprimées). Seule interface : boîtes de dialogue natives ;
- `--arriere-plan` : instance unique (`Global\PartageWiFi.Auto`), règle pare-feu `PartageWiFi Auto`,
  sondage du point d'accès natif toutes les 2 s (moteur démarré/arrêté, interface suivie),
  journal `logs\partage-wifi-auto.log`. Ne pilote jamais le point d'accès lui-même.
