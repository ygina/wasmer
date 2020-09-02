//! Package the binary and inputs into an independent executable unit.
use std::collections::HashSet;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use bincode;
use flate2::{Compression, write::GzEncoder};
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
    pub internal: PkgConfig,
    /// Package result
    result: Option<PkgResult>,
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
pub struct PkgConfig {
    /// Path to the binary
    pub binary_path: Option<PathBuf>,
    /// Pre-opened directories
    pub preopened: Vec<PathBuf>,
    /// Arguments
    pub args: Vec<String>,
    /// Environment variables
    pub envs: Vec<String>,
}

// fn print_fs(path: &Path, level: usize) -> io::Result<()> {
//     let prefix = (0..level).map(|_| "--").collect::<String>();
//     let filename = path.file_name().unwrap().to_str().unwrap();
//     if path.is_dir() {
//         println!("{}{}/", prefix, filename);
//         for entry in fs::read_dir(path)? {
//             let path = entry?.path();
//             print_fs(&path, level + 1)?;
//         }
//     } else {
//         println!("{}{}", prefix, filename);
//     }
//     Ok(())
// }

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
    /// Unwrap the result.
    fn result(&mut self) -> &mut PkgResult {
        self.result.as_mut().unwrap()
    }

    /// Take the result.
    pub fn take_result(&mut self) -> Option<PkgResult> {
        self.result.take()
    }

    /// Indicate this file was accessed and must be preserved in the archive.
    /// The file is in its original state from before execution. It already
    /// existed prior to execution and has not yet been modified.
    ///
    /// Returns whether the path was newly added.
    pub fn touch_path(&mut self, path: &Path) -> bool {
        let new_path = self.root.path().join(path);
        if !new_path.exists() && !self.created.contains(path) {
            // Copy the path to the new path if the new path doesn't exist
            if path.is_dir() {
                fs::create_dir_all(new_path).expect("unvalidated WASI");
            } else {
                match new_path.parent() {
                    Some(parent) => fs::create_dir_all(parent)
                        .expect("unvalidated WASI"),
                    None => {},
                };
                fs::copy(path, new_path).expect("unvalidated WASI");
            }
            true
        } else {
            false
        }
    }

    /// Create a file. Indicate this file was newly created and future accesses
    /// to this file should not preserve anything in the input archive.
    ///
    /// The operation should already have been validated by the actual WASI
    /// implementation. That is, the parent directories should already exist,
    /// while the file itself should not.
    pub fn create_file(&mut self, path: &Path) {
        debug!("create_file {:?}", path);
        fs::File::create(self.result().root.path().join(path))
            .expect("unvalidated WASI");
        self.created.insert(path.to_path_buf());
    }

    /// Create a directory. Indicate this directory was newly created and
    /// future accesses to this file should not preserve anything in the input
    /// archive.
    ///
    /// The operation should already have been validated by the actual WASI
    /// implementation. That is, the parent directories should already exist,
    /// while the directory itself should not.
    pub fn create_dir(&mut self, path: &Path) {
        debug!("create_dir {:?}", path);
        unimplemented!("create_dir {:?}", path)
    }

    /// Create empty files with the appropriate filenames in the path on the
    /// output root.
    ///
    /// The operation should have already been validated by the actual WASI
    /// implementation. That is, the path should be a directory and its file
    /// names should have already been read.
    pub fn read_dir(&mut self, path: &Path) {
        debug!("read_dir {:?}", path);
        unimplemented!("read_dir {:?}", path)
    }

    /// Rename a path.
    ///
    /// The operation should already have been validated by the actual
    /// WASI implementation. That is, the old path should already exist.
    pub fn rename_path(&mut self, old_path: &Path, new_path: &Path) {
        debug!("rename {:?} {:?}", old_path, new_path);
        fs::rename(
            self.result().root.path().join(old_path),
            self.result().root.path().join(new_path),
        ).expect("unvalidated WASI");
        self.created.insert(new_path.to_path_buf());
        self.touch_path(old_path);
    }

    /// Delete a path.
    ///
    /// The operation should already have been validated by the actual
    /// WASI implementation. That is, the path should already exist.
    pub fn delete_path(&mut self, path: &Path) {
        debug!("delete {:?}", path);
        fs::remove_file(self.result().root.path().join(path))
            .expect("unvalidated WASI");
        self.touch_path(path);
    }

    /// Write bytes to a path.
    ///
    /// The operation should already have been validated by the actual
    /// WASI implementation. That is, the path should already exist.
    /// The operation appends the bytes to the existing file.
    pub fn write_path(&mut self, path: &Path, bytes: &Vec<u8>) {
        debug!("write {:?} {} bytes", path, bytes.len());
        fs::write(self.result().root.path().join(path), &bytes[..])
            .expect("unvalidated WASI");
        self.touch_path(path);
    }

    /// Write bytes to stdout.
    pub fn write_stdout(&mut self, mut bytes: Vec<u8>) {
        self.result().stdout.append(&mut bytes);
    }

    /// Write bytes to stderr.
    pub fn write_stderr(&mut self, mut bytes: Vec<u8>) {
        self.result().stderr.append(&mut bytes);
    }

    /// Log package information.
    pub fn log_package(&self) -> io::Result<()> {
        println!("Writing package.");
        println!("preopened: {:?}", self.internal.preopened);
        println!("args: {:?}", self.internal.args);
        println!("envs: {:?}", self.internal.envs);
        println!("binary: {} bytes", self.wasm_binary.len());
        // print_fs(self.root.path(), 0)?;
        println!("result: {:?}", self.result);
        Ok(())
    }

    /// Write the binary, the packaged root directory, and other package
    /// configurations into a zipped directory.
    ///
    /// package
    /// -- main.wasm
    /// -- config  # serialized PkgConfig
    /// -- root/
    /// -- -- ...
    pub fn zip_package(&self) -> io::Result<()> {
        // Add the wasm binary to the temporary root.
        let binary_path = self.root.path().join(self.internal.binary_path
            .as_ref()
            .expect("uninitialized binary path"));
        match binary_path.parent() {
            Some(parent) => fs::create_dir_all(parent)?,
            None => {},
        };
        let mut binary = fs::File::create(binary_path)?;
        binary.write_all(&self.wasm_binary)?;

        // Tar it up.
        use tar::{Builder, Header};
        let tar_gz = fs::File::create("package.tar.gz")?;
        let enc = GzEncoder::new(tar_gz, Compression::default());
        let mut tar = Builder::new(enc);
        tar.append_dir_all("root", self.root.path())?;

        // Tar the config.
        let config = bincode::serialize(&self.internal).unwrap();
        let mut header = Header::new_gnu();
        header.set_size(config.len() as _);
        header.set_cksum();
        tar.append_data(&mut header, "config", &config[..])?;
        tar.into_inner()?;
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
            internal: PkgConfig {
                binary_path: None,
                preopened: Vec::new(),
                args: Vec::new(),
                envs: Vec::new(),
            },
            result: Some(PkgResult {
                stdout: Vec::new(),
                stderr: Vec::new(),
                root: TempDir::new("wasmer").expect("failed to create tempdir"),
            }),
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

    /// Recursively copy a directory to the output root.
    fn copy_path_to_output(&mut self, path: &Path) -> io::Result<()> {
        if path.is_dir() {
            fs::create_dir(self.result().root.path().join(path))?;
            for entry in fs::read_dir(path)? {
                let path = entry?.path();
                self.copy_path_to_output(&path)?;
            }
        } else {
            fs::copy(path, self.result().root.path().join(path))?;
        }
        Ok(())
    }

    /// Set the preopened directories.
    pub fn preopen_dirs(mut self, preopened: Vec<PathBuf>) -> io::Result<Self> {
        for path in &preopened {
            fs::create_dir(self.root.path().join(path))?;
            self.copy_path_to_output(path)?;
        }
        self.internal.preopened = preopened;
        Ok(self)
    }
}
