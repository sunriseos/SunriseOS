# Updating the Rust Toolchain

SunriseOS builds with a specific version of the Rust Nightly compiler specified by the rust-toolchain file. If the Rust compiler was installed via `rustup`, `cargo` will automatically check this file and install the required version of the rust compiler, ensuring the user always builds SunriseOS with the right toolchain.

We will occasionally want to update the version of the Rust Compiler we use in order to make use of the latest language features or to get the latest bug fixes. To do so:

1. Go to [rustup component history] and find the newest version that have the following components set as "present" on all Tier 1 Targets:
    - cargo
    - clippy
    - rls
    - rust
    - rust-analysis
    - rust-docs
    - rust-src
    - rust-std
    - rustc
2. Set the `rust-toolchain` file at the root of the repo to `nightly-$LATEST_VER`. For instance, if the latest version to support all the requirements is 2019-07-15, then set the rust-toolchain file to `nightly-2019-07-15`.
3. Update `xargo` to the latest version. It likely contains fixes for latest rust changes (there are breaking changes to `no_std` builds from time to time).
4. Compile the whole project, and fix all the errors.
5. Update the `BUILDING.md` with the new minimum versions.

Note that sometimes, none of the versions visible on the website will have the required component. In such a case, you'll have to wait until upstream fixes the builds, or find an old build manually. Good luck.

[rustup component history]: https://rust-lang.github.io/rustup-components-history/