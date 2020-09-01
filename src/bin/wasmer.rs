#![deny(
    dead_code,
    nonstandard_style,
    unused_imports,
    unused_mut,
    unused_variables,
    unused_unsafe,
    unreachable_patterns
)]
extern crate structopt;
extern crate log;

use std::env;
use std::path::PathBuf;
use std::process::exit;

use structopt::{clap, StructOpt};

use wasmer::*;
use wasmer::executor::*;
#[cfg(feature = "managed")]
use wasmer_runtime_core::tiering::{run_tiering, InteractiveShellContext, ShellExitOperation};
use wasmer_runtime_core;

#[cfg(not(any(
    feature = "backend-cranelift",
    feature = "backend-llvm",
    feature = "backend-singlepass"
)))]
compile_error!("Please enable one or more of the compiler backends");

#[derive(Debug, StructOpt)]
#[structopt(name = "wasmer", about = "Wasm execution runtime.", author)]
/// The options for the wasmer Command Line Interface
enum CLIOptions {
    /// Run a WebAssembly file. Formats accepted: wasm, wat
    #[structopt(name = "run")]
    Run(Run),

    /// Wasmer cache
    #[structopt(name = "cache")]
    Cache(Cache),

    /// Validate a Web Assembly binary
    #[structopt(name = "validate")]
    Validate(Validate),

    /// Update wasmer to the latest version
    #[structopt(name = "self-update")]
    SelfUpdate,
}

#[derive(Debug, StructOpt)]
enum Cache {
    /// Clear the cache
    #[structopt(name = "clean")]
    Clean,

    /// Display the location of the cache
    #[structopt(name = "dir")]
    Dir,
}

#[derive(Debug, StructOpt)]
struct Validate {
    /// Input file
    #[structopt(parse(from_os_str))]
    path: PathBuf,

    #[structopt(flatten)]
    features: PrestandardFeatures,
}

fn validate_wasm(validate: Validate) -> Result<(), String> {
    let wasm_path = validate.path;
    let wasm_path_as_str = wasm_path.to_str().unwrap();

    let wasm_binary: Vec<u8> = utils::read_file_contents(&wasm_path).map_err(|err| {
        format!(
            "Can't read the file {}: {}",
            wasm_path.as_os_str().to_string_lossy(),
            err
        )
    })?;

    if !utils::is_wasm_binary(&wasm_binary) {
        return Err(format!(
            "Cannot recognize \"{}\" as a WASM binary",
            wasm_path_as_str,
        ));
    }

    wasmer_runtime_core::validate_and_report_errors_with_features(
        &wasm_binary,
        validate.features.into_backend_features(),
    )
    .map_err(|err| format!("Validation failed: {}", err))?;

    Ok(())
}

/// Runs logic for the `validate` subcommand
fn validate(validate: Validate) {
    match validate_wasm(validate) {
        Err(message) => {
            eprintln!("Error: {}", message);
            exit(-1);
        }
        _ => (),
    }
}

fn main() {
    // We try to run wasmer with the normal arguments.
    // Eg. `wasmer <SUBCOMMAND>`
    // In case that fails, we fallback trying the Run subcommand directly.
    // Eg. `wasmer myfile.wasm --dir=.`
    let options = CLIOptions::from_iter_safe(env::args()).unwrap_or_else(|e| {
        match e.kind {
            // This fixes a issue that:
            // 1. Shows the version twice when doing `wasmer -V`
            // 2. Shows the run help (instead of normal help) when doing `wasmer --help`
            clap::ErrorKind::VersionDisplayed | clap::ErrorKind::HelpDisplayed => e.exit(),
            _ => CLIOptions::Run(Run::from_args()),
        }
    });
    match options {
        CLIOptions::Run(mut options) => {
            run(&mut options);
        },
        #[cfg(not(target_os = "windows"))]
        CLIOptions::SelfUpdate => update::self_update(),
        #[cfg(target_os = "windows")]
        CLIOptions::SelfUpdate => {
            println!("Self update is not supported on Windows. Use install instructions on the Wasmer homepage: https://wasmer.io");
        }
        CLIOptions::Cache(cache) => match cache {
            Cache::Clean => {
                use std::fs;
                let cache_dir = get_cache_dir();
                if cache_dir.exists() {
                    fs::remove_dir_all(cache_dir.clone()).expect("Can't remove cache dir");
                }
                fs::create_dir_all(cache_dir.clone()).expect("Can't create cache dir");
            }
            Cache::Dir => {
                println!("{}", get_cache_dir().to_string_lossy());
            }
        },
        CLIOptions::Validate(validate_options) => {
            validate(validate_options);
        }
    }
}

#[test]
fn filesystem_cache_should_work() -> Result<(), String> {
    let wasmer_cache_dir = get_cache_dir();

    unsafe { FileSystemCache::new(wasmer_cache_dir).map_err(|e| format!("Cache error: {:?}", e))? };

    Ok(())
}
