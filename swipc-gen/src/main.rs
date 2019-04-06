#![feature(box_patterns)]

use std::path::Path;

mod gen_rust_code;

use gen_rust_code::generate_ipc;

fn main() {
    for arg in std::env::args().skip(1) {
        println!("{}", generate_ipc(Path::new(&arg), "libuser".to_string(), "vi".to_string(), "libuser".to_string()));
    }
}
