fn main() {
    println!("cargo:rerun-if-changed=linker-scripts/bootstrap.ld");
    println!("cargo:rerun-if-changed=linker-scripts/kernel.ld");
}