use cargo_5730;

fn main() {
  println!("cargo:rerun-if-changed=build-script/src/main.rs");

  cargo_5730::run_build_crate("build-script");
}