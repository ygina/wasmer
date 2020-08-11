//! Package the binary and inputs into an independent executable unit.
use tempdir::TempDir;

/// The serialized struct along with the compressed filesystem that can
/// independently reproduce the execution.
#[derive(Debug)]
#[repr(C)]
pub struct Pkg {
    /// Dummy value
    pub root: TempDir,
    /// Binary bytes
    pub wasm_binary: Vec<u8>,
    /// Internal package configurations
    pub internal: InternalPkg,
}

/// Package configurations that are not related to files in the filesystem.
#[derive(Debug)]
#[repr(C)]
pub struct InternalPkg {
    /// Pre-opened directories
    pub preopened: Vec<String>,
    /// Arguments
    pub args: Vec<String>,
    /// Environment variables
    pub environ: Vec<String>,
}

impl Drop for Pkg {
    fn drop(&mut self) {
        // Write the binary, the packaged root directory, and other
        // package configurations into a zipped directory.
        println!("Writing package.")
    }
}

impl Pkg {
    /// Instantiate a new package.
    pub fn new() -> Self {
        Pkg {
            root: TempDir::new("wasmer").expect("failed to create tempdir"),
            wasm_binary: Vec::new(),
            internal: InternalPkg {
                preopened: Vec::new(),
                args: Vec::new(),
                environ: Vec::new(),
            },
        }
    }
}
