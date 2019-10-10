//! SwIPC Code Generator
//!
//! This crate is responsible for generating client code from a [SwIPC
//! interface definition](https://github.com/reswitched/SwIPC).
//!
//! The client code will use [sunrise_libuser](../sunrise_libuser)'s IPC API.

#![feature(box_patterns)]

mod gen_rust_code;
mod itemmod;

pub use gen_rust_code::generate_ipc;
