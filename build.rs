extern crate bindgen;
extern crate cc;
extern crate pkg_config;

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=tc.h");
    println!("cargo:rerun-if-changed=netlink.h");
    println!("cargo:rerun-if-changed=libnetlink.h");
    println!("cargo:rerun-if-changed=libnetlink.c");

    // Probe libmnl as we depend on it
    // pkg_config::Config::new().probe("libmnl").unwrap();
    //
    println!("cargo:rustc-link-lib=dylib=mnl");

    // Build libnetlink
    cc::Build::new().file("libnetlink.c").compile("nn");

    let defs = bindgen::Builder::default()
        .header("defs.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .ignore_functions()
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    defs.write_to_file(out_path.join("defs_bindings.rs"))
        .expect("Couldn't write bindings!");

    let netlink = bindgen::Builder::default()
        .header("libnetlink.h")
        .allowlist_function("nlmsg.*")
        .allowlist_function("rtnl_.*")
        .allowlist_function("addattr.*")
        .allowlist_function("nl_.*")
        .allowlist_function("rta_.*")
        .allowlist_function("parse_.*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    netlink
        .write_to_file(out_path.join("netlink_bindings.rs"))
        .expect("Couldn't write bindings!");
}
