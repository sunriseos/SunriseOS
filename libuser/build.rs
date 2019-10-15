//! Build script in charge of handling swipc-gen job

// TODO: libstd should be able to use proc macros
// BODY: Because libstd fails when using proc macro, we had to move swipc-gen to a build.rs script, just like in the good ol' days. Thx I hate it.
// BODY:
// BODY: We should figure out why proc macros fail when cross-compiling libstd with xargo and fix it.

use std::env;
use std::fs::{self, File};
use std::io::Write as _;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use swipc_gen::generate_ipc;

/// Array containing all module names and id path to use with swipc-gen.
const MODULES_ARRAY: &[(&str, &str)] =
    &[
        ("sm", "../../ipcdefs/sm.id"),
        ("vi", "../../ipcdefs/vi.id"),
        ("ahci", "../../ipcdefs/ahci.id"),
        ("time", "../../ipcdefs/time.id"),
        ("fs", "../../ipcdefs/filesystem.id"),
        ("keyboard", "../../ipcdefs/keyboard.id"),
        ("ldr", "../../ipcdefs/loader.id"),
        ("twili", "../../ipcdefs/twili.id"),
        ("example", "../../ipcdefs/example.id"),
    ];

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("ipc_code.rs");
    let mut f = File::create(&dest_path).unwrap();

    let crate_name = std::env::var("CARGO_PKG_NAME").unwrap();
    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into()));


    for module in MODULES_ARRAY {
        let module_name = module.0;
        let module_path = module.1;

        let prefix = format!("sunrise_libuser::{}", module_name);

        let module_complete_path = root.join("src/").join(module_path);

        let id_file = fs::read_to_string(&module_complete_path).unwrap();

        let mut generated_mod = generate_ipc(&id_file, prefix, module_name.to_string(), crate_name.to_string(), false);

        // Force a rebuild if the SwIPC definition changes.
        writeln!(generated_mod).unwrap();

        writeln!(generated_mod, "/// Auto generated for rebuilding \"{}\"", module_complete_path.to_str().unwrap()).unwrap();
        writeln!(generated_mod, "const _: &[u8] = include_bytes!({:?});", module_complete_path.to_str().unwrap()).unwrap();

        f.write_all(generated_mod.as_bytes()).unwrap();
    }
}
