//! Generic test helpers
use crate::advisory::Advisory;
use crate::package::Package;
use crate::scan::{Branch, Branches};
use std::str::FromStr;

pub fn create_branches(names: &[&str]) -> Branches {
    Branches::init(
        &names
            .iter()
            .map(|&n| Branch::from_str(n).unwrap())
            .collect::<Vec<_>>(),
    )
    .unwrap()
}

pub fn adv(cve: &str) -> Advisory {
    cve.parse().unwrap()
}

pub fn pkg(p: &str) -> Package {
    p.parse().unwrap()
}

pub fn br(name: &str) -> Branch {
    Branch::new(name)
}
