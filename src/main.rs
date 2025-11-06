#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::env;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::collections::HashMap;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

/// Add these imports for native ashmaize
use hex;
use anyhow::{Result, anyhow};

// If using local crate name; adjust if the crate name differs in ce-ashmaize.
#[cfg(feature = "native_ashmaize")]
use ashmaize::{Rom, RomGenerationType, hash};

// Simple in-memory ROM cache keyed by rom_init hex string. Feature-gated.
#[cfg(feature = "native_ashmaize")]
fn rom_cache() -> &'static Mutex<HashMap<String, std::sync::Arc<Rom>>> {
    use std::sync::OnceLock;
    static CACHE: OnceLock<Mutex<HashMap<String, std::sync::Arc<Rom>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn handle_client(mut stream: TcpStream, mode: Arc<DaemonMode>) {
    let peer = stream.peer_addr().ok();
    let r = stream.try_clone();
    if r.is_err() {
        eprintln!("Failed clone stream");
        return;
    }
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => {
                // EOF
                break;
            }
            Ok(_) => {
                let pre = line.trim_end_matches(&['\r','\n'][..]).to_string();
                if pre.len() == 0 {
                    // ignore empty
                    continue;
                }

                let hash_hex = match &*mode {
                    DaemonMode::Demo => {
                        // demo hasher: sha256(pre) + sha512(...) -> hex
                        demo_hash_hex(pre.as_bytes())
                    }
                    DaemonMode::External { bin } => {
                        // call external binary with preimage as arg
                        match call_external_hash(bin, &pre) {
                            Ok(h) => h,
                            Err(e) => {
                                eprintln!("External hash failed: {:?}", e);
                                "err".to_string()
                            }
                        }
                    }
            DaemonMode::Native { rom_init } => {
                // Native: allow client to optionally prefix the preimage with
                // a rom hex and '|' separator: "<rom_hex>|<preimage>". If the
                // prefix is present we'll use that rom init for this hash.
                let (maybe_rom, actual_pre) = if let Some(pos) = pre.find('|') {
                    let (r, p) = pre.split_at(pos);
                    // skip the '|' char for p
                    (Some(r.trim()), p[1..].trim())
                } else {
                    (rom_init.as_deref(), pre.as_str())
                };

                // 👇 Log ROM prefix info
// Thêm biến static để đảm bảo chỉ in 1 lần
                use std::sync::Once;
                static PRINTED_ROM: Once = Once::new();

                if let Some(rhex) = maybe_rom {
                    if !rhex.is_empty() {
                        PRINTED_ROM.call_once(|| {
                            println!(
                                "[client {:?}] received ROM prefix (printed once):\n\
                                ────────────────────────────────────────────────\n\
                                len = {}\n\
                                first 64 chars = {}\n\
                                ────────────────────────────────────────────────",
                                peer,
                                rhex.len(),
                                &rhex[..rhex.len().min(64)]
                            );
                        });
                    }
                }


                        // Compute
                        match native_hash_hex(actual_pre, maybe_rom) {
                            Ok(h) => h,
                            Err(e) => {
                                eprintln!("Native hash failed: {:?}", e);
                                "err".to_string()
                            }
                        }
                    }
                };

                if let Err(e) = writeln!(stream, "{}", hash_hex) {
                    eprintln!("Failed write to client {:?}: {:?}", peer, e);
                    break;
                }
                if let Err(e) = stream.flush() {
                    eprintln!("Flush error: {:?}", e);
                    break;
                }
            }
            Err(e) => {
                eprintln!("Read error from client {:?}: {:?}", peer, e);
                break;
            }
        }
    }
}

fn demo_hash_hex(pre: &[u8]) -> String {
    use sha2::{Digest, Sha256, Sha512};
    let mut d1 = Sha256::new();
    d1.update(pre);
    let d1b = d1.finalize();

    let mut d2 = Sha512::new();
    d2.update(&d1b);
    d2.update(pre);
    let out = d2.finalize();

    hex::encode(out)
}

fn call_external_hash(bin: &str, pre: &str) -> Result<String, Box<dyn std::error::Error>> {
    let out = Command::new(bin)
        .arg(pre)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?
        .wait_with_output()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Ok(s)
}

enum DaemonMode {
    Demo,
    External { bin: String },
    /// Native holds optional rom init hex string (no_pre_mine).
    Native { rom_init: Option<String> },
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let mut mode = DaemonMode::Demo;
    let mut port = 4002u16;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--mode" => {
                i += 1;
                if i >= args.len() { break; }
                match args[i].as_str() {
                    "demo" => mode = DaemonMode::Demo,
                    "external" => mode = DaemonMode::External { bin: "ashmaize-cli".to_string() },
                    "native" => mode = DaemonMode::Native { rom_init: None },
                    _ => {}
                }
            }
            "--bin" => {
                i += 1;
                if i >= args.len() { break; }
                let b = args[i].clone();
                mode = DaemonMode::External { bin: b };
            }
            "--port" => {
                i += 1;
                if i >= args.len() { break; }
                port = args[i].parse().unwrap_or(4000);
            }
            "--rom" => {
                // allow passing no_pre_mine hex directly to daemon for native init
                i += 1;
                if i >= args.len() { break; }
                let hexs = args[i].clone();
                mode = match mode {
                    DaemonMode::Native { .. } => DaemonMode::Native { rom_init: Some(hexs) },
                    _ => DaemonMode::Native { rom_init: Some(hexs) },
                };
            }
            _ => {}
        }
        i += 1;
    }

    println!("Starting ashdaemon on 127.0.0.1:{} mode={}", port,
        match &mode {
            DaemonMode::Demo => "demo",
            DaemonMode::External{..} => "external",
            DaemonMode::Native { .. } => "native",
        });

    // If native mode with rom init provided, try to validate the ROM init hex once (optional)
    if let DaemonMode::Native { rom_init } = &mode {
        if let Some(hexs) = rom_init {
            // Validate that provided --rom is valid hex; fail fast if it's not.
            match hex::decode(hexs) {
                Ok(_) => println!("Native mode: preloading ROM init (len {})", hexs.len()),
                Err(e) => {
                    eprintln!("Invalid --rom hex provided: {}", e);
                    return Err(anyhow!("Invalid --rom hex: {}", e));
                }
            }
            // We do not keep the AshMaize instance global here because the library
            // may require thread-local state; instead we will create/initialize per-hash
            // or implement a global instance if library API supports it.
        }
    }

    let mode_arc = Arc::new(mode);
    let listener = TcpListener::bind(("127.0.0.1", port))?;

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let mode_c = mode_arc.clone();
                thread::spawn(move || handle_client(s, mode_c));
            }
            Err(e) => {
                eprintln!("Listener error: {:?}", e);
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
    Ok(())
}

/// Compute AshMaize hash hex using ce-ashmaize crate (native implementation).
/// 'rom_init_hex' is optional hex string (no_pre_mine) required by algorithm init.
/// Return lowercase hex string of hash bytes.
fn native_hash_hex(pre: &str, rom_init_hex: Option<&str>) -> Result<String> {
    let pre_bytes = pre.as_bytes();

    #[cfg(feature = "native_ashmaize")]
    {
        let key = rom_init_hex.unwrap_or("default").to_string();

        let rom_arc = {
            let cache = rom_cache();
            let mut m = cache.lock().unwrap();

            if let Some(r) = m.get(&key) {
                r.clone()
            } else {
                    let seed = if let Some(s) = rom_init_hex {
            // Scavenger gửi raw bytes → lấy nguyên bytes
            let bytes = s.as_bytes().to_vec();
            println!(
                "[native_hash_hex] Using RAW ROM init ({} bytes)",
                bytes.len()
            );
            bytes
        } else {
            b"default_seed".to_vec()
        };


                // init ROM
                let rom = Rom::new(
                    &seed,
                    RomGenerationType::TwoStep {
                        pre_size: 16 * 1024 * 1024, // 16MB
                        mixing_numbers: 4,
                    },
                    1024 * 1024 * 1024, // 1GB
                );

                let arc = std::sync::Arc::new(rom);
                m.insert(key.clone(), arc.clone());
                arc
            }
        };

        let hash_bytes = hash(pre_bytes, &rom_arc, 8, 256);
        return Ok(hex::encode(hash_bytes));
    }

    #[cfg(not(feature = "native_ashmaize"))]
    {
        anyhow::bail!(
            "Native AshMaize not enabled. Compile with --features native_ashmaize"
        );
    }
}

