//! Package the binary and inputs into an independent executable unit.
use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use tempdir::TempDir;

/// The serialized struct along with the compressed filesystem that can
/// independently reproduce the execution.
#[derive(Debug)]
#[repr(C)]
pub struct Pkg {
    /// Dummy value
    pub root: TempDir,
    /// Created files
    pub created: HashSet<PathBuf>,
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

fn print_fs(path: &Path, level: usize) -> io::Result<()> {
    let prefix = (0..level).map(|_| "--").collect::<String>();
    let filename = path.file_name().unwrap().to_str().unwrap();
    if path.is_dir() {
        println!("{}{}/", prefix, filename);
        for entry in fs::read_dir(path)? {
            let path = entry?.path();
            print_fs(&path, level + 1)?;
        }
    } else {
        println!("{}{}", prefix, filename);
    }
    Ok(())
}

impl Drop for Pkg {
    fn drop(&mut self) {
        // Write the binary, the packaged root directory, and other
        // package configurations into a zipped directory.
        println!("Writing package.");
        println!("preopened: {:?}", self.internal.preopened);
        println!("args: {:?}", self.internal.args);
        println!("envs: {:?}", self.internal.envs);
        println!("binary: {} bytes", self.wasm_binary.len());
        match print_fs(self.root.path(), 0) {
            Ok(()) => {},
            Err(e) => {
                println!("ERROR READING DIRECTORY: {:?}", e);
            }
        }
    }
}

impl Pkg {
    /// Indicate this file was accessed and must be preserved in the archive.
    /// The file is in its original state from before execution. It already
    /// existed prior to execution and has not yet been modified.
    ///
    /// Returns whether the path was newly added.
    pub fn add_path(&mut self, path: &Path) -> io::Result<bool> {
        let new_path = self.root.path().join(path);
        if !new_path.exists() && !self.created.contains(path) {
            // Copy the path to the new path if the new path doesn't exist
            if path.is_dir() {
                fs::create_dir_all(new_path)?;
            } else {
                match new_path.parent() {
                    Some(parent) => fs::create_dir_all(parent)?,
                    None => {},
                };
                fs::copy(path, new_path)?;
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Indicate this file was newly created and future accesses to this file
    /// should not preserve anything in the archive.
    pub fn create_path(&mut self, path: &Path) {
        self.created.insert(path.to_path_buf());
    }
}

impl Pkg {
    /// Instantiate a new package.
    pub fn new() -> Self {
        Pkg {
            root: TempDir::new("wasmer").expect("failed to create tempdir"),
            created: HashSet::new(),
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
    pub fn preopen_dirs(mut self, preopened: Vec<PathBuf>) -> io::Result<Self> {
        self.internal.preopened = preopened;
        for path in &self.internal.preopened {
            fs::create_dir(self.root.path().join(path))?;
        }
        Ok(self)
    }
}
