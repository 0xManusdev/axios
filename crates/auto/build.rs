//! Ressources Windows du binaire : manifeste (administrateur, DPI, contrôles v6), icône, version.
//! `compile_for` les réserve au binaire : le harnais de test de la bibliothèque reste non élevé.

fn main() {
    println!("cargo:rerun-if-changed=resources");
    embed_resource::compile_for(
        "resources/auto.rc",
        ["partage-wifi-auto"],
        embed_resource::NONE,
    )
    .manifest_required()
    .expect("compilation des ressources Windows");
}
