# Build Instructions

## Rust toolchain

SunriseOS is written entirely in Rust and only requires a working Rust Toolchain
of the right version to work. It is recommended to use `rustup` to manage your
Rust installation, as it will automatically download the right version of the
toolchain to build SunriseOS when running `cargo`.

If you don't want to (or can't) use `rustup`, you should check the
`rust-toolchain` version to find out which version of the rust compiler you
should install.

## Build orchestration

SunriseOS is made of many different components that work together to build the
full system. Manually building all the required parts would be tedious, so we
set up `cargo-make` to orchestrate the build.

It can be installed through `cargo install cargo-make`. You'll need to make sure
you have a version that meets our minimum required versions. Check out the
[versions section](#versions) to find out what the minimum version of cargo-make
is necessary to build SunriseOS.

We use quite a few other tools in the process of building SunriseOS. Thankfully,
cargo-make will take care of installing all the others, and of updating them if
needed. However, if a build fails, make sure to check out the [versions
section](#versions) and ensure all the tools are installed and have the
appropriate version.

## Building

To build, simply use `cargo make iso --profile production`. This will generate a
live CD called `os.iso` which can be booted from to run SunriseOS.
`cargo make iso` can be used to generate a live CD running in debug mode.

## Qemu

First, ensure you have qemu installed, as `cargo-make` will not automatically
install it (See the [version sections](#versions)). Then, run `cargo make qemu
--profile production` to build and run the kernel in QEmu. It will open a display
server on VNC port 5900 (overridable by setting the `VNC_PORT` environment
variable) through which the user can interact. Logs going over serial port will be
printed on stdout.

## Versions

- rust: `nightly-2019-15-07`
  - clippy
  - rust-src
- cargo-make: `0.22.0`
- xargo: `0.3.18`
- mkisofs-rs: `0.1.1`
- qemu-system-i386: `4.0.50`
- cargo-travis: `https://github.com/roblabla/cargo-travis` branch `doc-upload-target`
