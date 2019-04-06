#![feature(box_patterns)]

extern crate proc_macro;

use proc_macro::TokenStream;
use syn::{AttributeArgs, ItemMod, parse_macro_input, spanned::Spanned};
use darling::FromMeta;
use std::path::PathBuf;

mod gen_rust_code;

#[derive(Debug, FromMeta)]
struct MacroArgs {
    path: String,
    prefix: String,
}

#[proc_macro_attribute]
pub fn gen_ipc(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attr_args = parse_macro_input!(attr as AttributeArgs);
    let item = parse_macro_input!(item as ItemMod);

    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into()));

    if item.content.is_some() {
        return syn::Error::new(item.span(), "gen_ipc expected empty mod.").to_compile_error().into()
    }

    let args = match MacroArgs::from_list(&attr_args) {
        Ok(v) => v,
        Err(e) => { return e.write_errors().into(); }
    };

    let prefix = format!("{}::{}", args.prefix, item.ident);

    let crate_name = std::env::var("CARGO_PKG_NAME").unwrap();

    let s = gen_rust_code::generate_ipc(&root.join("src/").join(args.path), prefix, item.ident.to_string(), crate_name);

    s.parse().unwrap()
}
