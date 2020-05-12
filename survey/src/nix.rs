use anyhow::{ensure, Result};
use colored::*;
use crossbeam::channel::{unbounded, Receiver, Sender};
use crossbeam::queue::SegQueue;
use lazy_static::lazy_static;
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::BufWriter;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI16, Ordering};
use std::thread;
use std::time::Duration;
use subprocess::{Exec, Redirection::Pipe};

/// Input derivations as found in `nix show-derivation` output
#[derive(Debug, Clone, Deserialize)]
struct InputDrv(HashMap<String, Vec<String>>);

/// Build environment data as found in `nix show-derivation` output
#[derive(Debug, Clone, Deserialize)]
struct DrvEnv(HashMap<String, String>);

/// `nix show-derivation` output
#[derive(Debug, Clone, Deserialize)]
struct DrvInfo {
    #[serde(alias = "inputDrvs")]
    input_drvs: InputDrv,
    env: DrvEnv,
}

/// Nix attribute name (think `-A hello`)
type Attr = String;

/// Collects `nix show-derivation` output for a list of derivaions.
/// ## Returns
/// - Build inputs as list of derivation paths
/// - Constituent build artefacts as list of attribute names
fn show_derivation(drvs: &[DrvPath]) -> Result<(Vec<DrvPath>, Vec<Attr>)> {
    if drvs.is_empty() {
        return Ok((vec![], vec![]));
    }
    let mut args = vec![OsStr::new("show-derivation")];
    args.extend(drvs.iter().map(|d| d.as_os_str()));
    let json = Exec::cmd("nix").args(&args).stdout(Pipe).capture()?.stdout;
    let info: HashMap<String, DrvInfo> = serde_json::from_slice(&json)?;
    let inputs = info
        .values()
        .flat_map(|d| d.input_drvs.0.keys().map(|name| DrvPath::new(&name)))
        .collect();
    let constituents = info
        .values()
        .filter_map(|drv| {
            drv.env
                .0
                .get("constituents")
                .map(|c| c.trim().split_ascii_whitespace())
        })
        .flatten()
        .map(|c| c.to_string())
        .collect();
    Ok((inputs, constituents))
}

/// Derives specified attribute from release file (None for default attribute)
fn nix_instantiate(repo: &Path, attr: Option<&str>) -> Result<DrvPath> {
    let mut cmd =
        Exec::cmd("nix-instantiate").args(&["<nixpkgs/nixos/release-combined.nix>", "--quiet"]);
    if let Some(ref a) = attr {
        cmd = cmd.args(&["-A", a])
    }
    info!("{}", cmd.to_cmdline_lossy());
    let cap = cmd
        .env("NIX_PATH", "nixpkgs=.")
        .cwd(repo)
        .stdout(Pipe)
        .capture()?;
    ensure!(
        cap.success(),
        "nix-instatiate failed with {:?}",
        cap.exit_status
    );
    ensure!(!cap.stdout.is_empty(), "empty derivation path");
    Ok(DrvPath::new(cap.stdout_str().trim_end()))
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
struct DrvPath(PathBuf);

lazy_static! {
    static ref R_VERSION: Regex = Regex::new("^(.+?)-([0-9]).*$").unwrap();
}

impl DrvPath {
    fn new<P: AsRef<Path>>(p: P) -> Self {
        let p = p.as_ref();
        assert!(
            p.starts_with("/nix/store/"),
            "Derivation path does not start with /nix/store"
        );
        assert!(
            p.extension().unwrap() == "drv",
            "Derivation path must have 'drv' extension"
        );
        Self(p.to_owned())
    }

    fn has_version(&self) -> bool {
        R_VERSION.is_match(&self.0.to_string_lossy())
    }
}

impl Deref for DrvPath {
    type Target = Path;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Default)]
struct Seen<T: std::hash::Hash + Eq + std::fmt::Debug>(HashSet<T>);

impl<T: std::hash::Hash + Eq + std::fmt::Debug + Clone> Seen<T> {
    fn add(&mut self, elem: &T) {
        if !self.0.contains(elem) {
            self.0.insert(elem.clone());
        }
    }

    fn take_max(&mut self, from_queue: &SegQueue<T>, n: usize) -> Vec<T> {
        let mut res = Vec::with_capacity(n);
        while res.len() < n {
            if let Ok(elem) = from_queue.pop() {
                if self.contains(&elem) {
                    continue;
                }
                self.add(&elem);
                res.push(elem);
            } else {
                break;
            }
        }
        res
    }
}

impl<T: std::hash::Hash + Eq + std::fmt::Debug + Clone> Deref for Seen<T> {
    type Target = HashSet<T>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

static INFLIGHT: AtomicI16 = AtomicI16::new(0);

fn expand_runner(
    queue: &SegQueue<DrvPath>,
    instantiate: Sender<Attr>,
    scanner: Sender<Vec<DrvPath>>,
) -> Result<()> {
    let mut seen = Seen::default();
    loop {
        let len = queue.len();
        if len > 0 {
            let drvs = seen.take_max(queue, 30);
            let (inputs, constituents) = show_derivation(&drvs)?;
            scanner.send(drvs)?;
            for i in inputs {
                queue.push(i)
            }
            for c in constituents {
                INFLIGHT.fetch_add(1, Ordering::SeqCst);
                instantiate.send(c)?;
            }
        // len == 0
        } else {
            let inflight = INFLIGHT.load(Ordering::SeqCst);
            if inflight <= 0 {
                break;
            } else {
                debug!(
                    "{} derivation(s) instantiating",
                    inflight.to_string().green()
                );
                thread::sleep(Duration::new(2, 0));
            }
        }
    }
    info!("Processed {} derivation paths", seen.len());
    Ok(())
}

fn instantiate_runner(repo: &Path, attrs: Receiver<Attr>, out: &SegQueue<DrvPath>) {
    for a in attrs {
        match nix_instantiate(repo, Some(&a)) {
            Ok(drv) => out.push(drv),
            Err(e) => warn!("Failed to instantiate {}: {}", a, e),
        }
        INFLIGHT.fetch_sub(1, Ordering::SeqCst);
    }
}

fn output_runner(drvs: Receiver<Vec<DrvPath>>, out: &mut File) -> Result<()> {
    let mut f = BufWriter::new(out);
    drvs.into_iter()
        .flat_map(|drv| drv.into_iter())
        .filter(|drv| drv.has_version())
        .map(|d| writeln!(f, "{}", d.display()))
        .collect::<Result<(), io::Error>>()?;
    Ok(())
}

pub fn all_derivations(repo: &Path) -> Result<PathBuf> {
    debug!("Expanding all derivations in {}", repo.display());
    let checkq = SegQueue::new();
    let mut outfile = tempfile::Builder::new()
        .prefix("vulnix_scan_drvs.")
        .tempfile()?;
    checkq.push(nix_instantiate(repo, None)?);
    crossbeam::scope(|s| -> Result<()> {
        let (out_tx, out_rx) = unbounded();
        let (inst_tx, inst_rx) = unbounded();
        let check_hdl = s.spawn(|_| expand_runner(&checkq, inst_tx, out_tx));
        let inst_hdl: Vec<_> = (1..num_cpus::get())
            .map(|_| {
                let rx = inst_rx.clone();
                s.spawn(|_| instantiate_runner(repo, rx, &checkq))
            })
            .collect();
        drop(inst_rx);
        let out_hdl = s.spawn(|_| output_runner(out_rx, outfile.as_file_mut()));
        check_hdl.join().expect("child thread panic")?;
        for hdl in inst_hdl {
            hdl.join().expect("child thread panic")
        }
        out_hdl.join().expect("child thread panic")
    })
    .unwrap()?;
    let (_, path) = outfile.keep()?;
    Ok(path)
}
