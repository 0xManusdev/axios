# axios v2 — contrat des nouvelles fonctions

Complète `CONTRACT.md` (toujours valable). Objectif : rendre réelles les fonctions de l'interface v2
(`app/src/v2`) aujourd'hui refusées par « Bientôt disponible ». Code de qualité : Rust idiomatique,
`clippy -D warnings` propre, tests unitaires pour toute logique pure, messages d'erreur courts en
français, commentaires en français, pas de `unwrap` hors tests.

Rappel du chemin des paquets (pw-engine) : les paquets des appareils (réseau du point d'accès,
192.168.137.0/24) destinés à internet sont capturés à la couche `NETWORK_FORWARD` (`forward_loop`) ;
TCP est réécrit vers le proxy local `gateway:8229` (`tcp_proxy`), UDP part par des sockets
(`udp::forward`, réponses fabriquées et injectées). Ce qui est **à destination du PC lui-même**
(DNS de Windows sur `gateway:53`, DHCP, partages…) n'est pas capturé.

---

## 1. pw-engine (crates/engine) — politique par appareil, DNS

### API publique ajoutée

```rust
// lib.rs : pub use policy::{Policy, DnsPolicy, Blocklist};

/// Politique appliquée au trafic des appareils. Remplacée d'un bloc par `Engine::set_policy`.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    /// Appareils sans accès à internet : tout paquet relayé est abandonné.
    pub blocked: HashSet<Ipv4Addr>,
    /// Débit maximal par appareil, en octets/s, appliqué séparément à chaque sens.
    pub limits: HashMap<Ipv4Addr, u64>,
    /// Isolation : abandonne le trafic relayé vers les réseaux privés/locaux
    /// (10/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10, multicast 224/4).
    pub isolate: bool,
    pub dns: DnsPolicy,
}

#[derive(Clone, Debug, Default)]
pub struct DnsPolicy {
    /// Résolveur imposé ; `None` = laisser passer vers le DNS de Windows.
    pub upstream: Option<Ipv4Addr>,
    /// Domaines bloqués (bloqueur de publicités) ; `None` = aucun blocage.
    pub blocklist: Option<Arc<Blocklist>>,
}

/// Ensemble de domaines bloqués ; un domaine est bloqué si lui ou l'un de ses parents l'est.
pub struct Blocklist { /* HashSet<Box<str>> en minuscules */ }
impl Blocklist {
    /// Format « hosts » (`0.0.0.0 domaine`, `127.0.0.1 domaine`, commentaires `#`)
    /// et format « une ligne = un domaine ». Ignore localhost & co.
    pub fn parse(text: &str) -> Blocklist;
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    /// `ads.example.com` est bloqué si `example.com` est dans la liste. Insensible à la casse,
    /// ignore un point final.
    pub fn contains(&self, domain: &str) -> bool;
}

impl Engine {
    /// Remplace la politique (non bloquant, effet immédiat sur les paquets suivants).
    /// Les connexions TCP en cours d'un appareil qui devient bloqué sont fermées.
    pub fn set_policy(&self, policy: Policy);
}

// stats.rs : EngineStats gagne
pub ads_blocked: u64,          // requêtes DNS refusées par la blocklist
```

### Comportement

- **Blocage** : dans `forward_loop`, un paquet dont la source est bloquée est abandonné (compteur
  `dropped`). `set_policy` ferme les connexions du proxy TCP appartenant à un appareil bloqué
  (à défaut, elles s'éteignent faute de paquets). Les requêtes DNS d'un appareil bloqué sont
  abandonnées elles aussi.
- **Limite de débit** : un seau à jetons par appareil et par sens (capacité ≈ 1 s de débit,
  minimum 16 Kio), partagé par toutes ses connexions. Proxy TCP : la boucle `pump` attend les
  jetons avant d'écrire (lissage). UDP : un paquet sans jetons disponibles est abandonné
  (police). Changer la limite s'applique aux connexions en cours. Logique du seau testée sans
  réseau (horloge injectable).
- **Isolation** : `forward_loop` abandonne les paquets dont la destination est privée/locale
  (liste ci-dessus) quand `isolate` est vrai. (L'accès au PC lui-même est fermé côté pare-feu,
  voir pw-winsys.)
- **DNS** : nouveau handle WinDivert couche `NETWORK`, filtre
  `inbound and udp and udp.DstPort == 53 and ip.DstAddr == <gateway> and ip.SrcAddr` dans le
  sous-réseau (ajouter le constructeur de filtre dans `subnet.rs`, testé). Pour chaque requête :
  1. source bloquée → abandon ;
  2. nom de la question dans la blocklist → réponse fabriquée `NXDOMAIN` (même ID, question
     recopiée, flags QR/RA, RCODE 3) envoyée de `gateway:53` vers l'appareil, injectée en sortie
     sur l'interface du point d'accès ; `ads_blocked += 1` ;
  3. `upstream` défini → requête relayée par socket UDP vers `upstream:53` (tâche tokio, délai
     3 s), réponse renvoyée de `gateway:53` vers l'appareil (même chemin que les réponses UDP) ;
  4. sinon → paquet réinjecté tel quel (même adresse WinDivert) : Windows répond normalement.
  Les requêtes DNS **relayées** (appareil qui interroge 8.8.8.8 directement, via `udp::forward`
  vers le port 53) passent aussi par la blocklist (réponse NXDOMAIN depuis l'adresse interrogée).
- Analyse DNS minimale en Rust pur (module `dns.rs`) : en-tête, première question (nom avec
  étiquettes, sans pointeurs de compression dans la question), construction de la réponse
  NXDOMAIN. Robuste aux paquets malformés (jamais de panique), testée.
- `set_policy` ne fait rien de coûteux (échange d'un `Arc<Policy>` derrière un verrou léger,
  par ex. `arc-swap` ou `RwLock<Arc<Policy>>`) : le chemin chaud lit la politique sans bloquer.

---

## 2. pw-winsys (crates/winsys) — connexions, bande amont, isolation, fabricant

### Connexion partagée (`hotspot.rs`)

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceKind { Wifi, Ethernet, Cellular }

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Source {
    /// Identifiant stable : GUID de l'adaptateur réseau (`NetworkAdapterId`), en texte.
    pub id: String,
    /// Nom du profil (SSID pour le Wi-Fi, « Ethernet »…).
    pub name: String,
    pub kind: SourceKind,
    /// Bande du Wi-Fi amont si connue (Wi-Fi uniquement).
    pub band: Option<Band>,
}

/// Connexions ayant accès à internet (niveau `InternetAccess`), celle par défaut en premier.
pub fn sources() -> Result<Vec<Source>>;
/// Connexion utilisée par le point d'accès : celle choisie si elle est disponible, sinon
/// celle d'internet par défaut. `None` s'il n'y en a aucune.
pub fn current_source() -> Result<Option<Source>>;
/// Choisit la connexion à partager (`None` = celle d'internet par défaut). Mémorisé dans le
/// processus ; toutes les fonctions du module (`info`, `start`, `configure`…) l'utilisent.
/// Si le point d'accès est actif, il est redémarré sur la nouvelle connexion.
pub fn select_source(id: Option<&str>) -> Result<HotspotInfo>;
```

- `manager()` utilise la connexion choisie (retrouvée par `NetworkAdapter.NetworkAdapterId`
  parmi `NetworkInformation::GetConnectionProfiles()`), sinon `GetInternetConnectionProfile`.
- Le message « pas de profil de connexion internet » ne doit plus inonder le journal : le
  consigner une seule fois par transition (présent → absent), en `debug` sinon.

### Bande du Wi-Fi amont (`net.rs` ou nouveau `wlan.rs`)

```rust
/// Bande de la connexion Wi-Fi de l'adaptateur `adapter_id` (GUID texte), via
/// `WlanOpenHandle` + `WlanQueryInterface(wlan_intf_opcode_channel_number)` :
/// canaux 1–14 → 2,4 GHz ; 32–177 → 5 GHz ; sinon `None`. `None` aussi en cas d'échec.
pub fn wifi_band(adapter_id: &str) -> Option<Band>;
```
(Fonction de classement canal → bande pure et testée.)

### Isolation (`firewall.rs`)

```rust
/// Active ou retire l'isolation : règles entrantes de **blocage** depuis `remote` (CIDR du point
/// d'accès), tous profils, nommées `axios-isolation-tcp|udp|icmp` :
/// TCP ports locaux sauf `keep_tcp` (le proxy), UDP sauf 53 (DNS) et 67 (DHCP), ICMPv4.
pub fn set_isolation(enabled: bool, remote: &str, keep_tcp: u16) -> Result<()>;
```
(Construction des plages de ports « tout sauf X » pure et testée : `1-8228,8230-65535`.)

### Fabricant (`mac.rs`, rendu public)

```rust
/// Adresse privée (bit « administré localement ») : MAC aléatoire des téléphones récents.
pub fn is_private(mac: &str) -> bool;
/// Fabricant d'après le préfixe OUI, table courte embarquée (Apple, Samsung, Xiaomi, Huawei,
/// Honor, Oppo, Vivo, Realme, OnePlus, Google, Tecno/Infinix/Itel (Transsion), Motorola, Nokia,
/// Sony, LG, Intel, Realtek, MediaTek, Qualcomm, Dell, HP, Lenovo, Asus, Acer, Microsoft,
/// Amazon, Nintendo, Raspberry Pi…) : plusieurs préfixes réels par fabricant. `None` si inconnu
/// ou privée.
pub fn vendor(mac: &str) -> Option<&'static str>;
```

---

## 3. Coquille (app/src-tauri) — commandes et événements v2

Fichiers JSON dans `%LOCALAPPDATA%\PartageWiFi\` : `settings.json`, `devices.json`
(alias, blocage, limite par MAC), `history.json` (heures sur 48 h, jours sur 60 jours, par
appareil), `blocklist.txt` (StevenBlack, téléchargée à l'activation, rafraîchie après 7 jours,
liste de secours embarquée si échec). Écritures atomiques (fichier temporaire + renommage).

Types JSON (camelCase) identiques à `app/src/v2/types.ts` : `Snapshot`, `Source`, `Device`,
`Stats`, `Usage`, `Settings`. Commandes :

| commande | arguments | retour |
|---|---|---|
| `get_snapshot` | — | `Snapshot` |
| `set_sharing` | `on` | `Snapshot` |
| `configure_network` | `ssid, passphrase, band` | `Snapshot` |
| `get_sources` | — | `Source[]` |
| `set_source` | `id` | `Snapshot` |
| `get_settings` | — | `Settings` |
| `update_settings` | `patch` (objet partiel) | `Settings` |
| `rename_device` | `id, alias` | — |
| `set_device_blocked` | `id, blocked` | — |
| `set_device_limit` | `id, limit` (Mb/s ou `null`) | — |
| `get_usage` | `range` (`24h`/`7d`/`30d`) | `Usage` |
| `quit_app` | — | — |

Événements : `snapshot` (Snapshot), `stats` (Stats, chaque seconde).
Réglages appliqués au démarrage et à chaque modification : `keepAlive` (maintien du point
d'accès), `isolate` (pare-feu + moteur), `adBlock`/`dns`/`customDns` (moteur), `defaultLimit`
(appareils sans limite propre), `autostart` (tâche planifiée), `shareOnLaunch`, `autoRestart`
(rallume le point d'accès quand la connexion revient s'il avait été coupé par sa perte),
`notifications` (notification Windows à la connexion d'un nouvel appareil).
