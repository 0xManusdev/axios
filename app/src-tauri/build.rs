//! Script de build : manifeste Windows personnalisé (administrateur, DPI, contrôles v6).

/// Manifeste de l'exécutable.
///
/// - `requireAdministrator` : WinDivert et le point d'accès exigent les droits admin.
/// - Common-Controls v6 : dépendance requise par Tauri (boîtes de dialogue, `TaskDialogIndirect`).
/// - DPI PerMonitorV2 : rendu net sur les écrans à échelles différentes.
const WINDOWS_MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <dependency>
    <dependentAssembly>
      <assemblyIdentity
        type="win32"
        name="Microsoft.Windows.Common-Controls"
        version="6.0.0.0"
        processorArchitecture="*"
        publicKeyToken="6595b64144ccf1df"
        language="*"
      />
    </dependentAssembly>
  </dependency>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}" />
    </application>
  </compatibility>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
    </windowsSettings>
  </application>
</assembly>
"#;

fn main() {
    let windows = tauri_build::WindowsAttributes::new().app_manifest(WINDOWS_MANIFEST);
    tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(windows))
        .expect("échec de la configuration de build Tauri");
}
