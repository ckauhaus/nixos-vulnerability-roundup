use super::Opt;
use crate::advisory::Advisory;
use crate::package::Package;

use anyhow::{bail, ensure, Context, Result};
use colored::*;
use git2::Repository;
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use smallstr::SmallString;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use subprocess::Exec;
use subprocess::ExitStatus::*;
use thiserror::Error;

pub type ScoreMap = HashMap<Advisory, f32>;

/// vulnix scan result item. vulnix output consists of a Vec of these.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct VulnixRes {
    #[serde(rename = "name")]
    pub pkg: Package,
    pub affected_by: Vec<Advisory>,
    #[serde(default)]
    pub cvssv3_basescore: ScoreMap,
}

pub type ScanByBranch = HashMap<Branch, Vec<VulnixRes>>;

/// NixOS release to scan. Note that the git rev/branch may have a different name than the release
/// name we publish.
#[derive(Debug, Clone, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Branch {
    /// NixOS release name to publish in tickets
    pub name: SmallString<[u8; 16]>,
    /// git parseable revspec, usually a branch name
    pub rev: SmallString<[u8; 16]>,
}

impl Branch {
    pub fn new(name: &str) -> Self {
        Self {
            name: SmallString::from_str(name),
            rev: SmallString::from_str(name),
        }
    }

    pub fn checkout(&self, repo: &Path) -> Result<()> {
        info!(
            "{} {} @ {}",
            "* Checking out".green().bold(),
            self.name.green().bold(),
            self.rev[0..11].yellow()
        );
        let status = Exec::cmd("git")
            .args(&["checkout", "-q", &self.rev])
            .cwd(repo)
            .join()
            .context("Cannot execute git")?;
        ensure!(
            status.success(),
            "Failed to check out git revision {}",
            self.rev.to_string()
        );
        Ok(())
    }

    /// Creates release derivation. Returns path to derivation file.
    pub fn instantiate(&self, repo: &Path) -> Result<PathBuf> {
        info!("{}", "* Instantiating...".green());
        crate::nix::all_derivations(repo)
    }

    /// Full path to JSON file containing vulnix scan results
    pub fn vulnix_json(&self, dir: &Path) -> PathBuf {
        dir.join(format!("vulnix.{}.json", self.name.as_str()))
    }

    /// Invokes `vulnix` on a derivation
    ///
    /// vulnix' output is saved to a JSON file iff parsing passed.
    fn vulnix(&self, drvfile: &Path, opt: &Opt) -> Result<Vec<VulnixRes>> {
        info!(
            "{} {}",
            "* Scanning derivations from".green(),
            drvfile.display()
        );
        let full_url = format!("{}/{}.toml", opt.whitelist_url, self.name.as_str());
        let full_wl = opt
            .whitelist_dir
            .join(format!("{}.toml", self.name.as_str()));
        let cmd = Exec::cmd(&opt.vulnix)
            .args(&["-j", "-R", "-w", &full_url, "-W"])
            .args(&[full_wl.as_os_str(), OsStr::new("-f"), drvfile.as_os_str()]);
        debug!("{}", cmd.to_cmdline_lossy().purple());
        let c = cmd.capture().context("Failed to read stdout from vulnix")?;
        match c.exit_status {
            Exited(e) if e <= 2 => (),
            _ => bail!("vulnix failed with exit status {:?}", c.exit_status),
        }
        let res = serde_json::from_slice(&c.stdout).context("vulnix JSON output parse error");
        // save for future reference
        let iterdir = opt.iterdir();
        let fname = self.vulnix_json(&iterdir);
        fs::create_dir_all(&iterdir)
            .and_then(|_| fs::write(&fname, c.stdout))
            .with_context(|| format!("Cannot write output to {:?}", fname))?;
        res
    }
}

lazy_static! {
    static ref BRANCHSPEC: Regex = Regex::new(r"^([^/=[:space:]]+)(=(\S+))?$").unwrap();
}

#[derive(Debug, Error)]
pub enum BranchErr {
    #[error("Invalid branch specification {spec}")]
    Invalid { spec: String },
}

impl FromStr for Branch {
    type Err = BranchErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match BRANCHSPEC.captures(s) {
            Some(cap) => {
                let name = &cap[1];
                match cap.get(3) {
                    Some(rev) => Ok(Branch {
                        name: name.into(),
                        rev: rev.as_str().into(),
                    }),
                    None => Ok(Branch::new(name)),
                }
            }
            None => Err(BranchErr::Invalid { spec: s.to_owned() }),
        }
    }
}

impl fmt::Display for Branch {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{}", self.name.as_str())
    }
}

fn resolve_rev(rev: &str, repo: &Repository) -> Result<String> {
    Ok(repo.revparse_single(rev)?.id().to_string())
}

#[derive(Default, Clone)]
pub struct Branches {
    specs: Vec<Branch>,
    repo: Option<PathBuf>,
}

impl Branches {
    /// List of branches without git repository. Used when loading previous scan results
    /// from directory.
    pub fn init(specs: &[Branch]) -> Result<Self> {
        let b = Self {
            specs: specs.to_owned(),
            ..Default::default()
        };
        for (idx, elem) in specs.iter().enumerate() {
            if specs.iter().skip(idx + 1).any(|s| s.name == elem.name) {
                bail!("Duplicate branch {}", elem.name.as_str());
            }
        }
        Ok(b)
    }

    /// List of branches with associated git repository. Used when scanning from source.
    pub fn with_repo(specs: &[Branch], repo: &Path) -> Result<Self> {
        let mut bs = Branches {
            repo: Some(repo.to_owned()),
            ..Branches::init(specs)?
        };
        let repo = Repository::open(repo).context("Cannot open repository")?;
        for mut b in bs.specs.iter_mut() {
            b.rev = SmallString::from(resolve_rev(b.rev.as_str(), &repo)?);
        }
        Ok(bs)
    }

    /// Reads previous scan results from a directory
    pub fn load(&self, dir: &Path) -> Result<ScanByBranch> {
        info!(
            "{} {}",
            "* Loading scan results from".green(),
            dir.display().to_string().yellow()
        );
        let mut sbb = ScanByBranch::new();
        for branch in self.iter() {
            let fname = branch.vulnix_json(dir);
            let f = File::open(&fname).with_context(|| format!("Cannot open file {:?}", fname))?;
            sbb.insert(
                branch.clone(),
                serde_json::from_reader(f).with_context(|| format!("JSON error in {:?}", fname))?,
            );
        }
        Ok(sbb)
    }

    /// Checks out all specified branches in turn, instantiates the release derivation and invokes
    /// vulnix on it.
    pub fn scan(&self, opt: &Opt) -> Result<ScanByBranch> {
        let repo = self
            .repo
            .as_ref()
            .expect("Bug: attempted to scan unspecified repository");
        let dir = opt.iterdir();
        fs::create_dir(&dir).ok();
        let mut sbb = ScanByBranch::new();
        for branch in self.iter() {
            branch.checkout(repo)?;
            let drvfile = branch.instantiate(repo)?;
            let scan = branch.vulnix(&drvfile, opt)?;
            sbb.insert(branch.clone(), scan);
        }
        Ok(sbb)
    }
}

impl Deref for Branches {
    type Target = [Branch];

    fn deref(&self) -> &Self::Target {
        &self.specs
    }
}

// === Tests ===

#[cfg(test)]
mod test {
    use super::*;
    use crate::tests::{br, create_branches};
    use libflate::gzip;
    use std::error::Error;
    use std::fs::read_to_string;
    use tar::Archive;
    use tempdir::TempDir;

    #[test]
    fn correct_branchspecs() {
        assert_eq!(
            Branch::from_str("nixos-18.09").unwrap(),
            Branch {
                name: "nixos-18.09".into(),
                rev: "nixos-18.09".into()
            }
        );
        assert_eq!(
            Branch::from_str("nixos-18.09=55f4cd48").unwrap(),
            Branch {
                name: "nixos-18.09".into(),
                rev: "55f4cd48".into()
            }
        );
        assert_eq!(
            Branch::from_str("nixos-18.09=origin/release-18.09").unwrap(),
            Branch {
                name: "nixos-18.09".into(),
                rev: "origin/release-18.09".into()
            }
        );
    }

    #[test]
    fn branchspec_invalid_chars() {
        assert!(Branch::from_str("nixos 18.09").is_err());
        assert!(Branch::from_str("origin/nixos-18.09").is_err());
    }

    #[test]
    fn branchspec_empty() {
        assert!(Branch::from_str("nixos=").is_err());
        assert!(Branch::from_str("=abcdefg").is_err());
    }

    #[test]
    fn no_duplicate_branch_names() {
        assert!(Branches::init(&[br("a"), br("b")]).is_ok());
        assert!(Branches::init(&[br("a"), br("b"), br("a")]).is_err());
    }

    #[test]
    fn load_json() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/iterations/1");
        let branches = create_branches(&["nixos-18.03", "nixos-18.09", "nixos-unstable"]);
        let res = branches.load(&dir).unwrap();
        assert_eq!(res.len(), 3);
        assert_eq!(res[&br("nixos-18.03")].len(), 2);
        assert_eq!(res[&br("nixos-18.09")].len(), 4);
        assert_eq!(res[&br("nixos-unstable")].len(), 3);
    }

    /// Little shell script which unconditionally writes the contents of
    /// fixtures/iterations/1/vulnix.nixos-18.09.json to stdout
    fn fake_vulnix() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/fake_vulnix")
    }

    #[test]
    fn run_vulnix() {
        let td = TempDir::new("test_write_json").unwrap();
        let mut opt = Opt::default();
        opt.vulnix = fake_vulnix();
        opt.basedir = td.path().to_path_buf();
        opt.iteration = 1;
        let orig_json = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/iterations/1/vulnix.nixos-18.09.json");
        let exp: Vec<VulnixRes> =
            serde_json::from_str(&read_to_string(&orig_json).unwrap()).unwrap();
        let res = br("nixos-18.09").vulnix(Path::new("result"), &opt).unwrap();
        assert_eq!(res, exp);
        // see if vulnix() saved original output
        assert_eq!(
            read_to_string(orig_json).expect("read original vulnix json"),
            read_to_string(td.path().join("1/vulnix.nixos-18.09.json"))
                .expect("cannot read saved vulnix results (file exists?)")
        );
    }

    #[test]
    fn resolve_branches() -> Result<(), Box<dyn Error>> {
        let tmp = TempDir::new("test_resolve_branches")?;
        let tarball = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/repo.tar.gz");
        Archive::new(gzip::Decoder::new(File::open(tarball)?)?).unpack(&tmp)?;
        let repo = Repository::open(&tmp.path().join("repo"))?;
        assert_eq!(
            "117a41dff30a62f2e4ef68c7e237ed497150b6dd",
            resolve_rev("117a41d", &repo)?
        );
        assert_eq!(
            "8dfec1442bf901fbfc09572ae0ea58d5ce8b4462",
            resolve_rev("master", &repo)?
        );
        assert_eq!(
            "12fe4b957c99f41b0885021599b445ac4a02623a",
            resolve_rev("b1", &repo)?
        );
        Ok(())
    }
}
