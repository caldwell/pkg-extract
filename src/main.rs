use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use indicatif::{HumanBytes, MultiProgress, ProgressBar, ProgressStyle};

mod crypto;
mod keys;
mod pkg;
mod pkg_entry_name;
mod psf;

/// Extract PlayStation 4 .pkg files.
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Path to the .pkg file
    pkg: PathBuf,

    /// Directory to extract into. The pkg's title id (and entitlement for DLC)
    /// is appended as a subdirectory. Defaults to the current directory.
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// List file paths without extracting anything.
    #[arg(short, long)]
    list: bool,

    /// With --list, include an ls-l style line per entry (mode, nlinks, uid, gid, size, mtime).
    #[arg(short, long)]
    verbose: bool,

    /// Print the pkg type (base game / patch / DLC) and exit with
    /// code 101, 102, or 103.
    #[arg(long)]
    check_type: bool,

    /// Print information about the pkg (validity, type, output destination).
    #[arg(short, long)]
    info: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("Error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run(args: &Args) -> Result<u8> {
    if !pkg::is_pkg_file(&args.pkg)? {
        eprintln!("{} doesn't appear to be a valid PKG file", args.pkg.display());
        return Ok(1);
    }
    if args.info {
        println!("{} is a valid PKG", args.pkg.display());
    }

    let mut pkg = pkg::Pkg::open(&args.pkg).context("Cannot open PKG file")?;
    let sfo = psf::Psf::parse(&pkg.sfo).context("Could not read SFO")?;

    let title_id = pkg.title_id().to_owned();
    let flags = pkg.flags_label();
    let category = sfo.get_string("CATEGORY").unwrap_or("");

    let output_root = args.output.clone().unwrap_or_else(|| PathBuf::from("."));
    let mut output = output_root.join(&title_id);

    let (return_code, kind): (u8, &str) = if flags.contains("PATCH") {
        (102, "game update")
    } else if category == "ac" {
        if let Some(cid) = sfo.get_string("CONTENT_ID") {
            if let Some(entitlement) = cid.split('-').nth(2) {
                output.push(entitlement);
            }
        } else if args.info {
            println!("PSF file: there is no CONTENT_ID");
        }
        (103, "dlc")
    } else {
        (101, "base game")
    };
    if args.info {
        println!("pkg is a {kind}");
    }

    if args.check_type {
        return Ok(return_code);
    }

    if args.info {
        let verb = if args.list { "Listing" } else { "Extracting pkg to" };
        println!("{verb} {}", output.display());
    }

    pkg.prepare(&output).context("Cannot prepare PKG")?;

    if args.list {
        for sce in pkg.sce_sys_entries() {
            let path = output.join("sce_sys").join(&sce.name);
            if args.verbose {
                print_verbose_sce_sys(sce.size, &path.display().to_string());
            } else {
                println!("{}", path.display());
            }
        }
        for (i, entry) in pkg.files().iter().enumerate() {
            if entry.is_pseudo() {
                continue;
            }
            let Some(p) = pkg.file_path(i) else { continue };
            let suffix = if entry.is_dir() { "/" } else { "" };
            let display = format!("{}{suffix}", p.display());
            if args.verbose {
                let inode = pkg.file_inode(i);
                print_verbose_pfs(inode, &display);
            } else {
                println!("{display}");
            }
        }
        return Ok(0);
    }

    pkg.create_directories().context("creating directories")?;
    extract_with_progress(&mut pkg)?;

    Ok(0)
}

fn extract_with_progress(pkg: &mut pkg::Pkg) -> Result<()> {
    let total_files = pkg.sce_sys_entries().len()
        + pkg.files().iter().filter(|e| e.is_file()).count();
    let total_bytes: u64 = pkg
        .sce_sys_entries()
        .iter()
        .map(|e| e.size as u64)
        .sum::<u64>()
        + pkg
            .files()
            .iter()
            .enumerate()
            .filter_map(|(i, e)| {
                e.is_file()
                    .then(|| pkg.file_inode(i).map(|ino| ino.size.max(0) as u64).unwrap_or(0))
            })
            .sum::<u64>();

    let multi = MultiProgress::new();

    let bar = multi.add(ProgressBar::new(total_bytes));
    bar.set_style(
        ProgressStyle::with_template(
            "{elapsed_precise} {wide_bar:.on_cyan/on_17} {eta_precise}",
        )
        .unwrap()
        .progress_chars("   "),
    );

    let path = multi.add(ProgressBar::new_spinner());
    path.set_style(
        ProgressStyle::with_template("{spinner} {prefix:<10.245} {msg:!.214}").unwrap(),
    );
    path.enable_steady_tick(Duration::from_millis(100));

    let totals = multi.add(ProgressBar::new_spinner());
    totals.set_style(
        ProgressStyle::with_template("{msg}, elapsed: {elapsed_precise}").unwrap(),
    );
    totals.enable_steady_tick(Duration::from_millis(100));

    let update_totals = |done: usize| {
        totals.set_message(format!(
            "{done}/{total_files} files, {} / {}",
            HumanBytes(bar.position()),
            HumanBytes(total_bytes),
        ));
    };
    update_totals(0);

    let mut done = 0usize;
    for i in 0..pkg.sce_sys_entries().len() {
        let name = pkg.sce_sys_entries()[i].name.clone();
        path.set_prefix(format!("[{}/{total_files}]", done + 1));
        path.set_message(format!("sce_sys/{name}"));
        pkg.extract_sce_sys(i, |n| bar.inc(n))
            .with_context(|| format!("extracting sce_sys/{name}"))?;
        done += 1;
        update_totals(done);
    }

    for i in 0..pkg.file_count() {
        if !pkg.files()[i].is_file() {
            continue;
        }
        let display = pkg
            .file_path(i)
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        path.set_prefix(format!("[{}/{total_files}]", done + 1));
        path.set_message(display);
        pkg.extract_file(i, |n| bar.inc(n))
            .with_context(|| format!("extracting file index {i}"))?;
        done += 1;
        update_totals(done);
    }

    bar.finish();
    path.finish_and_clear();
    totals.finish();
    Ok(())
}

fn print_verbose_sce_sys(size: u32, path: &str) {
    println!(
        "{:10} {:>3} {:>5} {:>5} {:>10}  {:19}  {}",
        "----------", "-", "-", "-", size, "-", path
    );
}

fn print_verbose_pfs(inode: Option<&pkg::Inode>, path: &str) {
    match inode {
        Some(ino) => println!(
            "{} {:>3} {:>5} {:>5} {:>10}  {}  {}",
            format_mode(ino.mode),
            ino.nlink,
            ino.uid,
            ino.gid,
            ino.size,
            format_time(ino.mtime_sec),
            path,
        ),
        None => println!(
            "{:10} {:>3} {:>5} {:>5} {:>10}  {:19}  {}",
            "----------", "-", "-", "-", "-", "-", path
        ),
    }
}

fn format_mode(mode: u16) -> String {
    let ty = match mode & 0o170000 {
        0o040000 => 'd',
        0o100000 => '-',
        _ => '?',
    };
    let bit = |b: u16, ch: char| if mode & b != 0 { ch } else { '-' };
    format!(
        "{ty}{}{}{}{}{}{}{}{}{}",
        bit(0o400, 'r'), bit(0o200, 'w'), bit(0o100, 'x'),
        bit(0o040, 'r'), bit(0o020, 'w'), bit(0o010, 'x'),
        bit(0o004, 'r'), bit(0o002, 'w'), bit(0o001, 'x'),
    )
}

/// Formats a Unix timestamp as "YYYY-MM-DD HH:MM:SS" in UTC. Uses Hinnant's
/// civil-from-days algorithm so we don't need a date library for one call site.
fn format_time(secs: i64) -> String {
    let day = secs.div_euclid(86400);
    let tod = secs.rem_euclid(86400);
    let (y, m, d) = civil_from_days(day);
    let (hh, mm, ss) = (tod / 3600, (tod / 60) % 60, tod % 60);
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}:{ss:02}")
}

fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year as i32, m, d)
}
