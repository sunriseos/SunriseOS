//! SwIPC Code Generator
//!
//! Allows testing the gen_ipc crate easily.
//!
//! # Usage
//!
//! `cargo make swipc-gen prefix path` will generate a file under
//! `libuser/src/module.rs` containing the generated code. The module name is
//! derived from the last part of the `prefix`. All the user has to do to get
//! good compilation errors is change how the module is declared in libuser:
//!
//! ```
//! // Before:
//! #[gen_ipc(path = "../../ipcdefs/sm.id", prefix = "sunrise_libuser")]
//! pub mod sm {}
//!
//! // After:
//! pub mod sm;
//! ```
//!
//! # Example
//!
//! `cargo make swipc-gen sunrise_libuser::vi ipcdefs/vi.id`

#![feature(box_patterns)]

use std::path::PathBuf;
use std::fs::{self, File};
use std::io::Write;

mod gen_rust_code;

use gen_rust_code::generate_ipc;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
struct Opt {
    /// Path of the module to create, including the crate name.
    mod_path: String,
    /// SwIPC files to process
    #[structopt(name = "FILE", parse(from_os_str))]
    file: PathBuf,
}


fn main() {
    let opt = Opt::from_args();

    let id_file = fs::read_to_string(opt.file).unwrap();
    // Get crate name from mod_path.
    let crate_name = opt.mod_path.split("::").nth(0).unwrap().to_string();

    // Mod name is the last part of the prefix.
    let mod_name = opt.mod_path.split("::").last().unwrap().to_string();


    let mut path = PathBuf::from("libuser/src/");
    for item in opt.mod_path.split("::").skip(1) {
        path.push(item);
    }
    path.set_extension("rs");

    let mut file = File::create(path).unwrap();
    file.write_all(generate_ipc(&id_file, opt.mod_path.clone(), mod_name, crate_name, true).as_bytes()).unwrap();
}
