//! Package the binary and inputs into an independent executable unit.
use std::path::PathBuf;
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
    pub preopened: Vec<PathBuf>,
    /// Arguments
    pub args: Vec<Vec<u8>>,
    /// Environment variables
    pub envs: Vec<Vec<u8>>,
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
                envs: Vec::new(),
            },
        }
    }

    /// Set the wasm binary.
    pub fn wasm_binary(mut self, wasm_binary: Vec<u8>) -> Self {
        self.wasm_binary = wasm_binary;
        self
    }

    /// Set the arguments.
    pub fn args(mut self, args: Vec<Vec<u8>>) -> Self {
        self.internal.args = args;
        self
    }

    /// Set the environment variables.
    pub fn envs(mut self, envs: &Vec<(&str, &str)>) -> Self {
        for (key, value) in envs {
            let length = key.len() + value.len() + 1;
            let mut byte_vec = Vec::with_capacity(length);

            byte_vec.extend_from_slice(key.as_bytes());
            byte_vec.push(b'=');
            byte_vec.extend_from_slice(value.as_bytes());

            self.internal.envs.push(byte_vec);
        }
        self
    }

    /// Set the preopened directories.
    pub fn preopen_dirs(mut self, preopened: Vec<PathBuf>) -> Self {
        self.internal.preopened = preopened;
        self
    }
}
