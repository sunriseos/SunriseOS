#![feature(external_doc)]
#![deny(intra_doc_link_resolution_failure)]

#![doc(include = "../README.md")]

fn main() {}

pub mod building {
    #![doc(include = "../BUILDING.md")]
}
pub mod updating_rust_version {
    #![doc(include = "../UPDATE_RUST.md")]
}

pub mod security_architecture {
    #![doc(include = "../SECURITY_ARCHITECTURE.md")]
}

// TODO: Add design goals documentation.
// BODY: Add documentation about the design goals of SunriseOS.
// BODY: This should include:
// BODY:
// BODY: - Simple to build
// BODY:   - Requires only a rust toolchain that can be installed straight from rustup
// BODY: - Simple to install
// BODY: - Every piece should be documented such that an outsider may understand what we're up to.
// BODY: - Only support modern hardware