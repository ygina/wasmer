//! Package the binary and inputs into an independent executable unit.
use std::collections::HashSet;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use bincode;
use tempdir::TempDir;

/// The serialized struct along with the compressed filesystem that can
/// independently reproduce the execution.
#[derive(Debug)]
#[repr(C)]
pub struct Pkg {
    /// Input files required to replicate the computation
    pub root: TempDir,
    /// Created files
    pub created: HashSet<PathBuf>,
    /// Binary bytes
    pub wasm_binary: Vec<u8>,
    /// Internal package configurations
    pub internal: InternalPkg,
    /// Package result
    result: PkgResult,
}

/// Package result.
#[derive(Debug)]
#[repr(C)]
pub struct PkgResult {
    /// Stdout
    pub stdout: Vec<u8>,
    /// Stderr
    pub stderr: Vec<u8>,
    /// Output filesystem
    pub root: TempDir,
}

/// Package configurations that are not related to files in the filesystem.
#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct InternalPkg {
    /// Path to the binary
    pub binary_path: Option<PathBuf>,
    /// Pre-opened directories
    pub preopened: Vec<PathBuf>,
    /// Arguments
    pub args: Vec<String>,
    /// Environment variables
    pub envs: Vec<String>,
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
        match self.log_package() {
            Ok(()) => {},
            Err(e) => println!("ERROR LOGGING PACKAGE: {:?}", e),
        };
        match self.zip_package() {
            Ok(()) => {},
            Err(e) => println!("ERROR ZIPPING PACKAGE: {:?}", e),
        };
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

    /// Write bytes to stdout.
    pub fn write_stdout(&mut self, mut bytes: Vec<u8>) {
        self.result.stdout.append(&mut bytes);
    }

    /// Write bytes to stderr.
    pub fn write_stderr(&mut self, mut bytes: Vec<u8>) {
        self.result.stderr.append(&mut bytes);
    }

    /// Log package information.
    pub fn log_package(&self) -> io::Result<()> {
        println!("Writing package.");
        println!("preopened: {:?}", self.internal.preopened);
        println!("args: {:?}", self.internal.args);
        println!("envs: {:?}", self.internal.envs);
        println!("binary: {} bytes", self.wasm_binary.len());
        print_fs(self.root.path(), 0)?;
        println!("result: {:?}", self.result);
        Ok(())
    }

    /// Write the binary, the packaged root directory, and other package
    /// configurations into a zipped directory.
    ///
    /// package
    /// -- main.wasm
    /// -- config  # serialized InternalPkg
    /// -- root/
    /// -- -- ...
    pub fn zip_package(&self) -> io::Result<()> {
        let dir = Path::new("package");
        fs::create_dir(dir)?;

        // Wasm binary
        let binary_path = self.root.path().join(self.internal.binary_path
            .as_ref()
            .expect("uninitialized binary path"));
        match binary_path.parent() {
            Some(parent) => fs::create_dir_all(parent)?,
            None => {},
        };
        let mut binary = fs::File::create(binary_path)?;
        binary.write_all(&self.wasm_binary)?;
        // Config
        let mut config = fs::File::create(dir.join("config"))?;
        config.write_all(&bincode::serialize(&self.internal).unwrap())?;
        // Root
        fs::rename(self.root.path(), dir.join("root/"))?;
        Ok(())
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
                binary_path: None,
                preopened: Vec::new(),
                args: Vec::new(),
                envs: Vec::new(),
            },
            result: PkgResult {
                stdout: Vec::new(),
                stderr: Vec::new(),
                root: TempDir::new("wasmer").expect("failed to create tempdir"),
            },
        }
    }

    /// Set the wasm binary.
    pub fn wasm_binary(
        mut self,
        binary_path: &Path,
        wasm_binary: Vec<u8>,
    ) -> Self {
        self.internal.binary_path = Some(binary_path.to_path_buf());
        self.wasm_binary = wasm_binary;
        self
    }

    /// Set the arguments.
    pub fn args(mut self, args: Vec<String>) -> Self {
        self.internal.args = args;
        self
    }

    /// Set the environment variables.
    pub fn envs(mut self, envs: &Vec<(&str, &str)>) -> Self {
        for (key, value) in envs {
            let env_var = format!("{}={}", key, value);
            self.internal.envs.push(env_var);
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
