use std::path::Path;
use std::process::Command;

fn main() {
    let libdir = "libs/builddir";

    // If the FAEST build directory doesn't exist, try to build it with meson/ninja (best-effort).
    if !Path::new(libdir).exists() {
        eprintln!("FAEST builddir not found, attempting meson/ninja build in libs/");
        let _ = Command::new("meson").args(["setup", "builddir"]).current_dir("libs").status();
        let _ = Command::new("ninja").args(["-C", "builddir"]).current_dir("libs").status();
    }

    // Compile the small C wrapper (libs/faest_wrapper.c) so we have stable symbols to call.
    // Optionally compile the C wrapper if FAEST_BUILD_WRAPPER=1 is set in the environment.
    if std::env::var("FAEST_BUILD_WRAPPER").unwrap_or_default() == "1" {
        if Path::new("libs/faest_wrapper.c").exists() {
            cc::Build::new()
                .file("libs/faest_wrapper.c")
                .include(libdir)
                .include("libs")
                .compile("faest_wrapper");
        }
    }

    // Tell cargo to link the FAEST library produced by Meson/Ninja.
    // Use the dynamic library when available to avoid thin-archive linking issues.
    println!("cargo:rustc-link-search=native={}", libdir);
    println!("cargo:rustc-link-lib=dylib=faest");

    // Re-run build script if anything under libs changes.
    println!("cargo:rerun-if-changed=libs/");
}
