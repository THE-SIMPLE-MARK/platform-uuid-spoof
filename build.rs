extern crate cc;

fn main() {
    cc::Build::new()
        .file("vendor/fishhook/fishhook.c")
        .compile("libfishhook.a");
    println!("cargo:rerun-if-changed=vendor/fishhook/fishhook.c");
    println!("cargo:rerun-if-changed=vendor/fishhook/fishhook.h");
}
