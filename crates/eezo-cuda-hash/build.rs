// =============================================================================
// T91.0 — CUDA BLAKE3 build script
//
// This build script detects whether the CUDA toolchain is available and emits
// a cfg flag `eezo_cuda_build_present` if it is.
//
// Behavior:
// - When CUDA is present (nvcc found): emit `cargo:rustc-cfg=eezo_cuda_build_present`
// - When CUDA is not present: do not emit the cfg, allowing stub code to compile
//
// The Rust code uses `#[cfg(eezo_cuda_build_present)]` to conditionally compile
// real CUDA initialization vs. stub code that returns RuntimeUnavailable.
// =============================================================================

use std::env;
use std::process::Command;

fn main() {
    // Tell Cargo to re-run this script if CUDA_PATH changes
    println!("cargo:rerun-if-env-changed=CUDA_PATH");
    println!("cargo:rerun-if-env-changed=PATH");

    // Tell Cargo about our custom cfg to avoid warnings
    println!("cargo::rustc-check-cfg=cfg(eezo_cuda_build_present)");

    // Detect CUDA availability by looking for nvcc
    let cuda_available = detect_cuda();

    if cuda_available {
        println!("cargo:warning=eezo-cuda-hash: CUDA toolchain detected (nvcc found)");
        println!("cargo:rustc-cfg=eezo_cuda_build_present");
    } else {
        println!("cargo:warning=eezo-cuda-hash: CUDA toolchain not detected (nvcc not found); using stub implementation");
    }
}

/// Detect whether CUDA toolchain is available by checking for nvcc.
fn detect_cuda() -> bool {
    // Method 1: Check if nvcc is in PATH
    if which::which("nvcc").is_ok() {
        return true;
    }

    // Method 2: Check CUDA_PATH environment variable
    if let Ok(cuda_path) = env::var("CUDA_PATH") {
        let nvcc_path = std::path::Path::new(&cuda_path).join("bin").join("nvcc");
        if nvcc_path.exists() {
            return true;
        }
        // Also try nvcc.exe on Windows
        let nvcc_exe_path = std::path::Path::new(&cuda_path).join("bin").join("nvcc.exe");
        if nvcc_exe_path.exists() {
            return true;
        }
    }

    // Method 3: Check common CUDA installation paths
    let common_paths = [
        "/usr/local/cuda/bin/nvcc",
        "/opt/cuda/bin/nvcc",
        "C:\\Program Files\\NVIDIA GPU Computing Toolkit\\CUDA\\v12.0\\bin\\nvcc.exe",
        "C:\\Program Files\\NVIDIA GPU Computing Toolkit\\CUDA\\v11.8\\bin\\nvcc.exe",
    ];

    for path in &common_paths {
        if std::path::Path::new(path).exists() {
            return true;
        }
    }

    // Method 4: Try running nvcc --version
    if let Ok(output) = Command::new("nvcc").arg("--version").output() {
        if output.status.success() {
            return true;
        }
    }

    false
}
