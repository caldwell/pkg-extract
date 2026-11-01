use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};

mod crypto;
mod keys;
mod pkg;
mod pkg_entry_name;
mod psf;

fn main() -> ExitCode {
    let mut args = std::env::args_os();
    let _prog = args.next();

    let Some(input) = args.next() else {
        eprintln!("usage: pkg-extract <pkg-file> [<output-dir>|--check-type]");
        return ExitCode::from(1);
    };
    let input = PathBuf::from(input);
    let second = args.next();

    let check_type = second
        .as_deref()
        .map(|s| s == std::ffi::OsStr::new("--check-type"))
        .unwrap_or(false);
    let no_output_arg = second.is_none();
    let output_dir = if check_type || no_output_arg {
        PathBuf::new()
    } else {
        PathBuf::from(second.unwrap())
    };

    let result = run(&input, &output_dir, check_type);

    if no_output_arg && result.is_ok() {
        println!("\nPress [enter] to exit.");
        let _ = std::io::stdin().read_line(&mut String::new());
    }

    match result {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("Error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run(input: &Path, output_dir: &Path, check_type_only: bool) -> Result<u8> {
    if !pkg::is_pkg_file(input)? {
        println!("{} doesn't appear to be a valid PKG file", input.display());
        println!("\nTHE END {}", input.display());
        return Ok(0);
    }
    println!("{} is a valid PKG\n", input.display());

    let mut pkg = pkg::Pkg::open(input).context("Cannot open PKG file")?;
    let sfo = psf::Psf::parse(&pkg.sfo).context("Could not read SFO")?;

    let title_id = pkg.title_id().to_owned();
    let flags = pkg.flags_label();
    let category = sfo.get_string("CATEGORY").unwrap_or("");

    let mut output = output_dir.join(&title_id);
    let return_code: u8 = if flags.contains("PATCH") {
        println!("pkg is a game update");
        let mut s = output.into_os_string();
        s.push("-patch");
        output = PathBuf::from(s);
        102
    } else if category == "ac" {
        println!("pkg is a dlc");
        if let Some(cid) = sfo.get_string("CONTENT_ID") {
            let parts: Vec<&str> = cid.split('-').collect();
            if parts.len() >= 3 {
                output.push(parts[2]);
            }
        } else {
            println!("PSF file there is no CONTENT_ID");
        }
        103
    } else {
        println!("pkg is a base game");
        101
    };

    if check_type_only {
        return Ok(return_code);
    }

    println!("Extracting pkg to {}", output.display());
    std::fs::create_dir_all(&output).ok();
    pkg.extract(&output).context("Cannot extract PKG file")?;

    let n = pkg.file_count();
    for i in 0..n {
        print!("\r      Extracting file {} of {}", i + 1, n);
        std::io::stdout().flush().ok();
        pkg.extract_file(i)
            .with_context(|| format!("extracting file index {i}"))?;
    }
    println!();
    println!("\nTHE END {}", input.display());

    Ok(0)
}
