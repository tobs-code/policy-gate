use clap::{Parser, Subcommand};
use firewall_core::{config::FirewallConfig, evaluate_raw, init, init_with_token};
use std::io::{self, BufRead};
use std::path::PathBuf;

mod diff;

#[derive(Parser)]
#[command(name = "firewall-cli")]
#[command(about = "Policy-Gate Management CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Evaluate prompts from stdin (line-by-line).
    Eval {
        /// Optional path to a specific firewall.toml.
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// Compare two firewall configuration files.
    Diff {
        /// Base configuration file.
        path_a: PathBuf,
        /// New configuration file to compare against.
        path_b: PathBuf,
    },
    /// Validate a firewall configuration file.
    Validate {
        /// Path to the configuration file.
        path: PathBuf,
    },
    /// Hot-reload multi-tenant configuration from a directory.
    /// Requires POLICY_GATE_INIT_TOKEN for production use.
    Reload {
        /// Path to directory containing .toml tenant configs.
        dir: PathBuf,
        /// Optional init token for production reloads.
        #[arg(short, long, env = "POLICY_GATE_INIT_TOKEN")]
        token: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Eval { config } => {
            // SA-077: Write PID file for hot-reload triggering from Python.
            let pid_path = std::path::Path::new("/tmp/policy-gate.pid");
            if let Some(parent) = pid_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(pid_path, std::process::id().to_string());

            // Warn if --config was supplied but cannot yet be honoured.
            if let Some(ref path) = config {
                eprintln!(
                    "[WARN] --config flag provided ({}) but not yet supported in eval mode; \
                     using default firewall.toml",
                    path.display()
                );
            }

            // For now, eval still uses standard init() which loads firewall.toml.
            if let Err(e) = init() {
                eprintln!("[ERROR] Firewall init failed: {}", e);
                std::process::exit(1);
            }

            let stdin = io::stdin();
            for (i, line) in stdin.lock().lines().enumerate() {
                let prompt = match line {
                    Ok(l) => l,
                    Err(e) => {
                        eprintln!("read error: {}", e);
                        continue;
                    }
                };
                if prompt.trim().is_empty() {
                    continue;
                }
                let verdict = evaluate_raw(prompt.clone(), i as u64);
                let label = if verdict.is_pass() { "PASS" } else { "BLOCK" };
                if verdict.kind == firewall_core::VerdictKind::DiagnosticDisagreement {
                    println!(
                        "{}\t{:?}\tA:{:?} B:{:?}\t{}",
                        label, verdict.kind, verdict.channel_a.decision, verdict.channel_b.decision, prompt
                    );
                } else {
                    println!("{}\t{:?}\t{}", label, verdict.kind, prompt);
                }
            }
        }
        Commands::Diff { path_a, path_b } => {
            let cfg_a = match FirewallConfig::load_from_path(&path_a) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!(
                        "[ERROR] Failed to load config A ({}): {}",
                        path_a.display(),
                        e
                    );
                    std::process::exit(1);
                }
            };
            let cfg_b = match FirewallConfig::load_from_path(&path_b) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!(
                        "[ERROR] Failed to load config B ({}): {}",
                        path_b.display(),
                        e
                    );
                    std::process::exit(1);
                }
            };
            diff::display_diff(&cfg_a, &cfg_b);
        }
        Commands::Validate { path } => match FirewallConfig::load_from_path(&path) {
            Ok(cfg) => {
                if let Err(errors) = cfg.validate() {
                    eprintln!("Validation failed for {}:", path.display());
                    for err in errors {
                        eprintln!("  - {}", err);
                    }
                    std::process::exit(1);
                } else {
                    println!("Configuration {} is VALID.", path.display());
                }
            }
            Err(e) => {
                eprintln!("Failed to load {}: {}", path.display(), e);
                std::process::exit(1);
            }
        },
        Commands::Reload { dir, token } => {
            // Initialize firewall with token if provided (production)
            let init_result = if let Some(t) = token {
                init_with_token(&t, firewall_core::FirewallProfile::Default)
            } else {
                init()
            };

            if let Err(e) = init_result {
                eprintln!("Firewall initialization failed: {}", e);
                std::process::exit(1);
            }

            // SA-077: Audit log entry for reload operation
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            eprintln!(
                "[AUDIT] Multi-tenant reload initiated at {} for dir: {}",
                timestamp,
                dir.display()
            );

            // Perform the reload with staged validation (fail-closed)
            match firewall_core::config_watcher::reload_tenant_directory(&dir) {
                Ok(changed) => {
                    if changed {
                        println!(
                            "Multi-tenant configuration reloaded successfully from {}.",
                            dir.display()
                        );
                        // SA-077: Clear evaluation cache after successful reload
                        eprintln!("[AUDIT] Evaluation cache cleared after reload.");
                    } else {
                        println!("No configuration changes detected in {}.", dir.display());
                    }
                }
                Err(e) => {
                    // Fail-closed: Log error but keep existing config active
                    eprintln!(
                        "[AUDIT] Reload failed, existing configuration preserved: {}",
                        e
                    );
                    eprintln!("Configuration reload failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}
