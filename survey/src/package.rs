use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct Package {
    pub name: String,
    v_idx: usize,
}

impl Package {
    #[cfg(test)]
    fn new<S: AsRef<str>>(pname: S, version: S) -> Self {
        let pname = pname.as_ref();
        Self {
            name: pname.to_string() + "-" + version.as_ref(),
            v_idx: pname.len() + 1,
        }
    }

    pub fn pname(&self) -> &str {
        &self.name[..self.v_idx - 1]
    }

    #[cfg(test)]
    fn version(&self) -> &str {
        &self.name[self.v_idx..]
    }
}

impl fmt::Display for Package {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{}", self.name)
    }
}

lazy_static! {
    /// See parseDrvName in https://nixos.org/nix/manual/#ssec-builtins
    static ref VERSION_SPLIT: Regex = Regex::new(r"-[0-9]").unwrap();
}

#[derive(Debug, Error)]
pub enum PackageErr {
    #[error("Failed to find version in derivation name '{}'", name)]
    Version { name: String },
}

impl FromStr for Package {
    type Err = PackageErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(m) = VERSION_SPLIT.find(s) {
            Ok(Self {
                name: s.to_owned(),
                v_idx: m.start() + 1,
            })
        } else {
            Err(PackageErr::Version { name: s.to_owned() })
        }
    }
}

impl TryFrom<String> for Package {
    type Error = <Self as FromStr>::Err;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        FromStr::from_str(&s)
    }
}

// === Tests ===

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn package_name_version() {
        let p = Package::new("openssl", "1.0.2d");
        assert_eq!("openssl", p.pname());
        assert_eq!("1.0.2d", p.version());
    }

    #[test]
    fn format() {
        let p = Package::new("binutils", "2.32.1");
        assert_eq!("binutils-2.32.1", p.to_string());
    }

    #[test]
    fn parse() {
        assert_eq!(
            Package::new("exiv2", "0.27.1"),
            "exiv2-0.27.1".parse().unwrap()
        );
        assert!("exiv2".parse::<Package>().is_err());
        assert!("linux-kernel".parse::<Package>().is_err());
        assert_eq!(
            Package::new("linux-kernel", "5.2"),
            "linux-kernel-5.2".parse().unwrap()
        );
    }
}
