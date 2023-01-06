#![deny(rust_2018_idioms)]
use migration_helpers::common_migrations::{AddMetadataMigration, SettingMetadata};
use migration_helpers::{migrate, Result};
use std::process;

/// We updated the 'affected-services' list metadata for 'settings.oci-defaults'
/// to include itself and containerd on upgrade, and to remove those values on
/// downgrade, depending on the running variant.
fn run() -> Result<()> {
    if cfg!(variant_runtime = "k8s") {
        migrate(AddMetadataMigration(&[SettingMetadata {
            metadata: &["affected-services"],
            setting: "settings.oci-defaults",
        }]))?
    };

    Ok(())
}

// Returning a Result from main makes it print a Debug representation of the error, but with Snafu
// we have nice Display representations of the error, so we wrap "main" (run) and print any error.
// https://github.com/shepmaster/snafu/issues/110
fn main() {
    if let Err(e) = run() {
        eprintln!("{}", e);
        process::exit(1);
    }
}
