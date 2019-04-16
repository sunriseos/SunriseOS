//! SwIPC Code Generator
//!
//! Allows testing the gen_ipc crate easily.

#![feature(box_patterns)]

use std::path::PathBuf;
use std::fs;

mod gen_rust_code;

use gen_rust_code::generate_ipc;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
struct Opt {
    /// Path to the module to generate code under, as a ::-delimited path.
    prefix: String,
    /// Name of the module to create.
    mod_name: String,
    /// SwIPC files to process
    #[structopt(name = "FILE", parse(from_os_str))]
    files: Vec<PathBuf>,
}


fn main() {
    let opt = Opt::from_args();

    for file in opt.files {
        let id_file = fs::read_to_string(file).unwrap();
        // Get crate name from prefix. In the future, those might need to be
        // different, but let's keep the CLI simple for now.
        let crate_name = opt.prefix.split("::").nth(0).unwrap().to_string();
        println!("{}", generate_ipc(&id_file, opt.prefix.clone(), opt.mod_name.clone(), crate_name));
    }
}
