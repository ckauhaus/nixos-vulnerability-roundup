use crate::advisory::Advisory;
use crate::package::Package;
use crate::scan::{Branch, ScanByBranch, ScoreMap};

use float_ord::FloatOrd;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fmt::Write as FWrite;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq)]
pub struct Ticket {
    iteration: u32,
    pkg: Package,
    affected: HashMap<Advisory, Detail>,
}

impl Ticket {
    /// Creates a new Ticket with empty 'affected' list.
    pub fn new(iteration: u32, pkg: Package) -> Self {
        Self {
            iteration,
            pkg,
            affected: HashMap::new(),
        }
    }

    /// Local file name (excluding directory)
    pub fn file_name(&self) -> PathBuf {
        PathBuf::from(format!("ticket.{}.md", self.pkg.name))
    }

    /// Package name + version
    pub fn name(&self) -> &str {
        &self.pkg.name
    }

    /// Package name without version
    pub fn pname(&self) -> &str {
        &self.pkg.pname()
    }

    /// Writes ticket to disk, optionally with a pointer to a tracker issue
    pub fn write<P: AsRef<Path>>(&self, file_name: P, issue_url: Option<&str>) -> io::Result<()> {
        let f = fs::File::create(file_name)?;
        write!(&f, "{}", self)?;
        if let Some(url) = issue_url {
            writeln!(&f, "\n<!-- {} -->", url)?;
        }
        Ok(())
    }

    pub fn summary(&self) -> String {
        let num = self.affected.len();
        let advisory = if num == 1 { "advisory" } else { "advisories" };
        format!(
            "Vulnerability roundup {}: {}: {} {}",
            self.iteration, self.pkg.name, num, advisory
        )
    }

    pub fn body(&self) -> String {
        let mut res = String::with_capacity(1000);
        writeln!(
            &mut res,
            "\
[search](https://search.nix.gsc.io/?q={pname}&i=fosho&repos=NixOS-nixpkgs), \
[files](https://github.com/NixOS/nixpkgs/search?utf8=%E2%9C%93&q={pname}+in%3Apath&type=Code)\n\
        ",
            pname = self.pname()
        )
        .ok();
        let mut adv: Vec<(&Advisory, &Detail)> = self.affected.iter().collect();
        adv.sort_unstable_by(cmp_score);
        for (advisory, details) in adv {
            writeln!(
                &mut res,
                "* [ ] [{adv}](https://nvd.nist.gov/vuln/detail/{adv}) {details}",
                adv = advisory,
                details = details
            )
            .ok();
        }
        let relevant: HashSet<&Branch> = self
            .affected
            .values()
            .flat_map(|d| d.branches.iter())
            .collect();
        let mut relevant: Vec<String> = relevant
            .into_iter()
            .map(|b| format!("{}: {}", b.name.as_str(), &b.rev.as_str()[..11]))
            .collect();
        relevant.sort();
        writeln!(
            &mut res,
            "\nScanned versions: {}. May contain false positives.",
            relevant.join("; ")
        )
        .ok();
        res
    }
}

impl fmt::Display for Ticket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}\n\n{}", self.summary(), self.body())
    }
}

#[derive(Debug, Clone, Default, PartialEq, PartialOrd)]
pub struct Detail {
    branches: Vec<Branch>,
    score: Option<f32>,
}

impl Detail {
    fn new(score: Option<f32>) -> Self {
        Self {
            score,
            ..Default::default()
        }
    }

    fn add(&mut self, branch: Branch) {
        self.branches.push(branch);
    }
}

impl fmt::Display for Detail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(score) = self.score {
            write!(f, "CVSSv3={:1.1} ", score)?;
        }
        let b: Vec<&str> = self.branches.iter().map(|b| b.name.as_str()).collect();
        write!(f, "({})", b.join(", "))
    }
}

fn cmp_score(a: &(&Advisory, &Detail), b: &(&Advisory, &Detail)) -> Ordering {
    let left = FloatOrd(a.1.score.unwrap_or(-1.0));
    let right = FloatOrd(b.1.score.unwrap_or(-1.0));
    match left.cmp(&right) {
        Ordering::Greater => Ordering::Less,
        Ordering::Less => Ordering::Greater,
        Ordering::Equal => a.0.cmp(&b.0),
    }
}

/// One ticket per package, containing scan results for all branches
pub fn ticket_list(iteration: u32, mut scan_by_branch: ScanByBranch) -> Vec<Ticket> {
    let mut scores = ScoreMap::default();
    // Step 1: for each pkgs, list all pairs (advisory, branch) in random order
    let mut pkgmap: HashMap<Package, Vec<(Advisory, Branch)>> = HashMap::new();
    for (branch, scan_results) in scan_by_branch.drain() {
        for res in scan_results {
            let e = pkgmap.entry(res.pkg).or_insert_with(Vec::new);
            e.extend(res.affected_by.into_iter().map(|adv| (adv, branch.clone())));
            scores.extend(&res.cvssv3_basescore);
        }
    }
    // Step 2: consolidate branches
    let mut tickets: Vec<Ticket> = pkgmap
        .into_iter()
        .map(|(pkg, mut adv)| {
            adv.sort(); // especially needed to get branch ordering right
            let mut t = Ticket::new(iteration, pkg);
            for (advisory, branch) in adv {
                let score = scores.get(&advisory);
                t.affected
                    .entry(advisory)
                    .or_insert_with(|| Detail::new(score.cloned()))
                    .add(branch)
            }
            t
        })
        .collect();
    tickets.sort_by(|a, b| a.pkg.cmp(&b.pkg));
    tickets
}

// === Tests ===

#[cfg(test)]
mod test {
    use super::*;
    use crate::scan::VulnixRes;
    use crate::tests::{adv, create_branches, pkg};
    use maplit::hashmap;

    /// Helper for quick construction of Detail structs
    fn det(branches: &[&str], score: Option<f32>) -> Detail {
        Detail {
            branches: branches.iter().map(|&b| Branch::new(b)).collect(),
            score,
        }
    }

    #[test]
    fn decode_scan_single_branch() {
        let scan = hashmap! {
            Branch::new("br1") => vec![
                VulnixRes {
                    pkg: pkg("ncurses-6.1"),
                    affected_by: vec![adv("CVE-2018-10754")],
                    .. Default::default()
                },
                VulnixRes {
                    pkg: pkg("libtiff-4.0.9"),
                    affected_by: vec![
                        adv("CVE-2018-17000"),
                        adv("CVE-2018-17100"),
                        adv("CVE-2018-17101")],
                    .. Default::default()
                },
            ]
        };
        assert_eq!(
            ticket_list(1, scan),
            &[
                Ticket {
                    iteration: 1,
                    pkg: pkg("libtiff-4.0.9"),
                    affected: hashmap! {
                        adv("CVE-2018-17000") => det(&["br1"], None),
                        adv("CVE-2018-17100") => det(&["br1"], None),
                        adv("CVE-2018-17101") => det(&["br1"], None),
                    },
                },
                Ticket {
                    iteration: 1,
                    pkg: pkg("ncurses-6.1"),
                    affected: hashmap! { adv("CVE-2018-10754") => det(&["br1"], None) },
                }
            ]
        );
    }

    #[test]
    fn decode_scan_multiple_branches() {
        let scan = hashmap! {
            Branch::new("br1") => vec![VulnixRes {
                pkg: pkg("libtiff-4.0.9"),
                affected_by: vec![adv("CVE-2018-17100"), adv("CVE-2018-17101")],
                cvssv3_basescore: hashmap! {
                    adv("CVE-2018-17100") => 8.8,
                    adv("CVE-2018-17101") => 8.7,
                },
            }],
            Branch::new("br2") => vec![VulnixRes {
                pkg: pkg("libtiff-4.0.9"),
                affected_by: vec![adv("CVE-2018-17101")],
                cvssv3_basescore: hashmap! { adv("CVE-2018-17101") => 8.7 }
            }],
        };
        assert_eq!(
            ticket_list(2, scan),
            &[Ticket {
                iteration: 2,
                pkg: pkg("libtiff-4.0.9"),
                affected: hashmap! {
                    adv("CVE-2018-17100") => det(&["br1"], Some(8.8)),
                    adv("CVE-2018-17101") => det(&["br1", "br2"], Some(8.7)),
                }
            }]
        );
    }

    #[test]
    fn rendered_ticket() {
        let br = create_branches(&[
            "br0=5d4a1a3897e2d674522bcb3aa0026c9e32d8fd7c",
            "br1=80738ed9dc0ce48d7796baed5364eef8072c794d",
        ]);
        let tkt = Ticket {
            iteration: 2,
            pkg: pkg("libtiff-4.0.9"),
            affected: hashmap! {
                adv("CVE-2018-17000") => Detail { branches: vec![br[0].clone()], score: None },
                adv("CVE-2018-17100") => Detail { branches: vec![br[0].clone()], score: Some(8.7) },
                adv("CVE-2018-17101") => Detail { branches: vec![br[0].clone(), br[1].clone()], score: Some(8.8) },
            },
        };
        // should be sorted by score in decreasing order, undefined scores last
        assert_eq!(
            tkt.to_string(),
            "\
Vulnerability roundup 2: libtiff-4.0.9: 3 advisories\n\
\n\
[search](https://search.nix.gsc.io/?q=libtiff&i=fosho&repos=NixOS-nixpkgs), \
[files](https://github.com/NixOS/nixpkgs/search?utf8=%E2%9C%93&q=libtiff+in%3Apath&type=Code)\n\
\n\
* [ ] [CVE-2018-17101](https://nvd.nist.gov/vuln/detail/CVE-2018-17101) CVSSv3=8.8 (br0, br1)\n\
* [ ] [CVE-2018-17100](https://nvd.nist.gov/vuln/detail/CVE-2018-17100) CVSSv3=8.7 (br0)\n\
* [ ] [CVE-2018-17000](https://nvd.nist.gov/vuln/detail/CVE-2018-17000) (br0)\n\
\n\
Scanned versions: br0: 5d4a1a3897e; br1: 80738ed9dc0. \
May contain false positives.\n\
        "
        );
    }

    #[test]
    fn print_only_relevant_branches() {
        let br = create_branches(&[
            "nixos-18.09=5d4a1a3897e2d674522bcb3aa0026c9e32d8fd7c",
            "nixos-unstable=80738ed9dc0ce48d7796baed5364eef8072c794d",
        ]);
        let tkt = Ticket {
            iteration: 1,
            pkg: pkg("libtiff-4.0.9"),
            affected: hashmap! {
                adv("CVE-2018-17100") => Detail { branches: vec![br[0].clone()], score: Some(8.8) }
            },
        };
        assert!(
            tkt.to_string()
                .contains("versions: nixos-18.09: 5d4a1a3897e. May"),
            format!("branch summary not correct:\n{}", tkt)
        );
    }

    #[test]
    fn cmp_score_ordering() {
        assert_eq!(
            cmp_score(
                &(&adv("CVE-2019-0001"), &det(&[], Some(5.1))),
                &(&adv("CVE-2019-0001"), &det(&[], Some(5.1)))
            ),
            Ordering::Equal
        );
        assert_eq!(
            cmp_score(
                &(&adv("CVE-2019-0001"), &det(&[], Some(5.0))),
                &(&adv("CVE-2019-0001"), &det(&[], Some(5.1)))
            ),
            Ordering::Greater
        );
        assert_eq!(
            cmp_score(
                &(&adv("CVE-2019-0001"), &det(&[], Some(0.0))),
                &(&adv("CVE-2019-0001"), &det(&[], None))
            ),
            Ordering::Less
        );
        assert_eq!(
            cmp_score(
                &(&adv("CVE-2019-10000"), &det(&[], Some(5.5))),
                &(&adv("CVE-2019-9999"), &det(&[], Some(5.5)))
            ),
            Ordering::Greater
        );
    }
}
