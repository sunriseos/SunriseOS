//! SwIPC Code Generator
//!
//! This crate is responsible for generating client code from a [SwIPC
//! interface definition](https://github.com/reswitched/SwIPC).
//!
//! The client code will use [sunrise_libuser](../sunrise_libuser)'s IPC API.

#![feature(box_patterns)]

extern crate proc_macro;

use proc_macro::TokenStream;
use syn::{AttributeArgs, parse_macro_input, spanned::Spanned};
use darling::FromMeta;
use std::path::PathBuf;
use std::fmt::Write;
use std::fs;

mod gen_rust_code;
mod itemmod;

use itemmod::ItemMod;

/// Attribute arguments for the gen_ipc macro.
#[derive(Debug, FromMeta)]
struct MacroArgs {
    /// Path to the SwIPC id file, relative to the crate's src directory.
    path: String,
    /// Path to the current module, as a ::-delimited token.
    prefix: String,
}

/// [gen_ipc] macro implementation. See module-level docs for more information.
#[proc_macro_attribute]
pub fn gen_ipc(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attr_args = parse_macro_input!(attr as AttributeArgs);
    let item = parse_macro_input!(item as ItemMod);

    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into()));

    if item.content.iter().any(|s| !s.1.is_empty()) {
        return syn::Error::new(item.span(), "gen_ipc expected empty mod.").to_compile_error().into()
    }

    let args = match MacroArgs::from_list(&attr_args) {
        Ok(v) => v,
        Err(e) => { return e.write_errors().into(); }
    };

    let prefix = format!("{}::{}", args.prefix, item.ident);

    let crate_name = std::env::var("CARGO_PKG_NAME").unwrap();

    let id_file = fs::read_to_string(&root.join("src/").join(&args.path)).unwrap();

    let mut generated_mod = gen_rust_code::generate_ipc(&id_file, prefix, item.ident.to_string(), crate_name, false);

    // Force a rebuild if the SwIPC definition changes.
    writeln!(generated_mod).unwrap();
    writeln!(generated_mod, "const _: &[u8] = include_bytes!(\"{}\");", args.path).unwrap();

    generated_mod.parse().unwrap()
}
