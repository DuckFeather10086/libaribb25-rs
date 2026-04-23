//! b25 - ARIB STD-B25 TS Descrambler (Rust)
//!
//! Usage: b25 [options] src.m2t dst.m2t [more pairs ...]
//!        b25 [options] - -        (read from stdin, write to stdout)
//!
//! Options:
//!   -r <round>     MULTI2 rounds (default: 4)
//!   -s <0|1>       0: keep null packets (default), 1: strip null packets
//!   -m <0|1>       0: ignore EMM (default), 1: send EMM to card
//!   -p <0|1>       0: no power-on control info, 1: show it (default)
//!   -v <0|1>       0: silent, 1: verbose (default)
//!   -a <0|1>       0: B-CAS mode (default), 1: A-CAS mode
//!   -S <level>     SIMD level: auto (default), scalar, neon, …
//!
//! Use "-" as the source or destination path to read from stdin / write to stdout.

use std::fs::File;
use std::io::{self, Read, Write, BufReader, BufWriter};
use std::time::Instant;

use aribb25::arib_std_b25::AribStdB25;
use aribb25::b_cas_card::{AcasMode, BCasCard};
use aribb25::error::B25Error;
use aribb25::multi2::SimdLevel;

const VERSION: &str = "0.2.10";

struct Options {
    round: u32,
    strip: bool,
    emm: bool,
    power_ctrl: bool,
    verbose: bool,
    acas: Option<AcasMode>,
    /// SIMD level requested by the user (or auto-detected).
    simd: SimdLevel,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            round: 4,
            strip: false,
            emm: false,
            power_ctrl: true,
            verbose: true,
            acas: None,
            simd: SimdLevel::detect(),
        }
    }
}

fn show_usage() {
    let detected = SimdLevel::detect();
    eprintln!("b25 - ARIB STD-B25 descrambler version {}", VERSION);
    eprintln!("usage: b25 [options] src.m2t dst.m2t [more pair ..]");
    eprintln!("       b25 [options] - -    (stdin -> stdout)");
    eprintln!("options:");
    eprintln!("  -r <round>   MULTI2 rounds (integer, default=4)");
    eprintln!("  -s <0|1>     0: keep null stream (default)");
    eprintln!("               1: strip null stream");
    eprintln!("  -m <0|1>     0: ignore EMM (default)");
    eprintln!("               1: send EMM to B-CAS card");
    eprintln!("  -p <0|1>     0: do nothing additionally");
    eprintln!("               1: show B-CAS EMM receiving request (default)");
    eprintln!("  -v <0|1>     0: silent");
    eprintln!("               1: show processing status (default)");
    eprintln!("  -a <0|1>     0: B-CAS mode (default)");
    eprintln!("               1: A-CAS mode");
    eprintln!("  -S <level>   MULTI2 SIMD level (default: auto)");
    eprintln!("               allowed values: {}", SimdLevel::build_levels().join(", "));
    eprintln!("               detected on this CPU: {}", detected.name());
    eprintln!("               'scalar' disables SIMD (useful for debugging)");
    eprintln!("               specifying a level above what the CPU supports is an error");
    eprintln!("  Use \"-\" as src or dst to read from stdin / write to stdout.");
}

fn parse_args(args: &[String]) -> Result<(Options, Vec<(String, String)>), String> {
    let mut opt = Options::default();
    let detected = SimdLevel::detect();
    let mut i = 1usize;

    while i < args.len() {
        let arg = &args[i];
        // "-" alone means stdin/stdout filename, not a flag.
        if !arg.starts_with('-') || arg == "-" {
            break;
        }
        if arg.len() < 2 {
            return Err(format!("unknown option '{}'", arg));
        }

        let flag = arg.chars().nth(1).unwrap();
        let inline_val: Option<&str> = if arg.len() > 2 { Some(&arg[2..]) } else { None };

        let get_int_val = |inline: Option<&str>, args: &[String], i: &mut usize| -> Result<i64, String> {
            let s = if let Some(v) = inline {
                v.to_owned()
            } else {
                *i += 1;
                args.get(*i).cloned().ok_or_else(|| format!("option '-{}' needs a value", flag))?
            };
            s.parse::<i64>().map_err(|_| format!("invalid value for '-{}': {}", flag, s))
        };

        let get_str_val = |inline: Option<&str>, args: &[String], i: &mut usize| -> Result<String, String> {
            if let Some(v) = inline {
                Ok(v.to_owned())
            } else {
                *i += 1;
                args.get(*i).cloned().ok_or_else(|| format!("option '-{}' needs a value", flag))
            }
        };

        match flag {
            'r' => { opt.round = get_int_val(inline_val, args, &mut i)? as u32; }
            's' => { opt.strip = get_int_val(inline_val, args, &mut i)? != 0; }
            'm' => { opt.emm   = get_int_val(inline_val, args, &mut i)? != 0; }
            'p' => { opt.power_ctrl = get_int_val(inline_val, args, &mut i)? != 0; }
            'v' => { opt.verbose    = get_int_val(inline_val, args, &mut i)? != 0; }
            'a' => {
                let v = get_int_val(inline_val, args, &mut i)?;
                opt.acas = Some(match v {
                    0 => AcasMode::BCas,
                    1 => AcasMode::ACas,
                    _ => return Err(format!("invalid '-a' value: {} (use 0 or 1)", v)),
                });
            }
            'S' => {
                let s = get_str_val(inline_val, args, &mut i)?;
                let level = SimdLevel::from_str(&s).ok_or_else(|| {
                    format!(
                        "unknown SIMD level '{}' — allowed: {}",
                        s,
                        SimdLevel::build_levels().join(", ")
                    )
                })?;
                // Refuse levels the CPU cannot execute.
                if level > detected {
                    return Err(format!(
                        "SIMD level '{}' is not supported by this CPU (detected: '{}')",
                        level.name(),
                        detected.name(),
                    ));
                }
                opt.simd = level;
            }
            _ => return Err(format!("unknown option '-{}'", flag)),
        }

        i += 1;
    }

    // Collect file pairs.
    let mut pairs = Vec::new();
    while i + 1 <= args.len() {
        if i + 1 == args.len() {
            // Odd leftover argument — no output file.
            return Err(format!("no output file specified for input '{}'", args[i]));
        }
        pairs.push((args[i].clone(), args[i + 1].clone()));
        i += 2;
    }

    if pairs.is_empty() {
        return Err("no input/output file pairs specified".to_owned());
    }

    Ok((opt, pairs))
}

fn process_file(src_path: &str, dst_path: &str, opt: &Options) -> Result<(), String> {
    // Open source (or use stdin when path is "-").
    let mut src_size: u64 = 0;
    let mut src: Box<dyn Read> = if src_path == "-" {
        Box::new(BufReader::with_capacity(64 * 1024, io::stdin()))
    } else {
        let f = File::open(src_path)
            .map_err(|e| format!("failed to open input '{}': {}", src_path, e))?;
        src_size = f.metadata().map(|m| m.len()).unwrap_or(0);
        Box::new(BufReader::with_capacity(64 * 1024, f))
    };

    // Open destination (or use stdout when path is "-").
    let mut dst: Box<dyn Write> = if dst_path == "-" {
        Box::new(BufWriter::with_capacity(64 * 1024, io::stdout()))
    } else {
        let f = File::create(dst_path)
            .map_err(|e| format!("failed to create output '{}': {}", dst_path, e))?;
        Box::new(BufWriter::with_capacity(64 * 1024, f))
    };

    // Create B-CAS card.
    let mut bcas = BCasCard::new();
    if let Some(mode) = opt.acas {
        bcas.set_acas_mode(mode)
            .map_err(|e| format!("set_acas_mode failed: {}", e))?;
    }
    bcas.init().map_err(|e| format!("B-CAS card init failed: {}", e))?;

    // Create decoder with the chosen SIMD level.
    let mut b25 = AribStdB25::new_with_simd(opt.simd);
    b25.set_multi2_round(opt.round);
    b25.set_strip(opt.strip);
    b25.set_emm_proc(opt.emm);
    b25.set_b_cas_card(bcas)
        .map_err(|e| format!("set_b_cas_card failed: {}", e))?;

    if opt.verbose {
        eprintln!("b25 version {} [SIMD: {}]", VERSION, opt.simd.name());
    }

    let start = Instant::now();
    let mut bytes_read: u64 = 0;
    let mut buf = vec![0u8; 64 * 1024];

    loop {
        let n = src.read(&mut buf)
            .map_err(|e| format!("read error: {}", e))?;
        if n == 0 {
            break;
        }

        bytes_read += n as u64;

        let warn = b25.put(&buf[..n]);
        let decrypted = match warn {
            Ok(_) => b25.get().map_err(|e| format!("get failed: {}", e))?,
            Err(B25Error::NoPat) | Err(B25Error::NoPmt) | Err(B25Error::NoEcm) => {
                eprintln!("error: {:?}", warn);
                let raw = b25.withdraw();
                if !raw.is_empty() {
                    let mut combined = raw;
                    combined.extend_from_slice(&buf[..n]);
                    combined
                } else {
                    buf[..n].to_vec()
                }
            }
            Err(e) => return Err(format!("put failed: {}", e)),
        };

        if !decrypted.is_empty() {
            dst.write_all(&decrypted)
                .map_err(|e| format!("write error: {}", e))?;
        }

        if opt.verbose {
            let elapsed = start.elapsed().as_millis();
            let mbps = if elapsed > 100 {
                (bytes_read as f64) / 1024.0 / (elapsed as f64)
            } else {
                0.0
            };
            if src_size > 0 {
                let pct = bytes_read as f64 / src_size as f64 * 100.0;
                eprint!("\rprocessing: {:5.2}% [{:6.2} MB/sec]", pct, mbps);
            } else {
                eprint!("\rprocessing: {:6.2} MB/sec", mbps);
            }
        }
    }

    // Flush remaining data.
    if let Err(e) = b25.flush() {
        eprintln!("\nwarning: flush failed: {}", e);
    }
    let tail = b25.get().map_err(|e| format!("final get failed: {}", e))?;
    if !tail.is_empty() {
        dst.write_all(&tail)
            .map_err(|e| format!("write error: {}", e))?;
    }

    dst.flush().map_err(|e| format!("flush error: {}", e))?;

    if opt.verbose {
        let elapsed = start.elapsed().as_millis();
        let mbps = if elapsed > 100 {
            (bytes_read as f64) / 1024.0 / (elapsed as f64)
        } else {
            0.0
        };
        eprintln!("\rprocessing: finish  [{:6.2} MB/sec]", mbps);
    }

    // Print per-program info.
    for info in b25.get_program_info() {
        if info.ecm_unpurchased_count > 0 {
            eprintln!("warning - unpurchased ECM detected");
            eprintln!("  channel:               {}", info.program_number);
            eprintln!("  unpurchased ECM count: {}", info.ecm_unpurchased_count);
            eprintln!("  last ECM error code:   {:04x}", info.last_ecm_error_code);
            eprintln!("  undecrypted TS packets:{}", info.undecrypted_packet_count);
            eprintln!("  total TS packets:      {}", info.total_packet_count);
        }
    }

    Ok(())
}

fn main() {
    // Detect CPU capabilities once at startup so that any mismatch between
    // what the OS reports and what the user requests is caught immediately,
    // before any descrambling work begins.
    let detected = SimdLevel::detect();

    let args: Vec<String> = std::env::args().collect();

    let (opt, pairs) = match parse_args(&args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {}", e);
            eprintln!("CPU SIMD capability: {}", detected.name());
            show_usage();
            std::process::exit(1);
        }
    };

    let mut had_error = false;
    for (src, dst) in &pairs {
        if let Err(e) = process_file(src, dst, &opt) {
            eprintln!("error processing '{}' -> '{}': {}", src, dst, e);
            had_error = true;
        }
    }

    if had_error {
        std::process::exit(1);
    }
}
