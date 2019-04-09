//! SwIPC Code Generator
//!
//! Allows testing the gen_ipc crate easily.

#![feature(box_patterns)]

use std::path::Path;
use std::fs;

mod gen_rust_code;

use gen_rust_code::generate_ipc;

fn main() {
    for arg in std::env::args().skip(1) {
        let id_file = fs::read_to_string(Path::new(&arg)).unwrap();
        println!("{}", generate_ipc(&id_file, "libuser".to_string(), "vi".to_string(), "libuser".to_string()));
    }
}
