use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

type Result<T, E = AdvErr> = std::result::Result<T, E>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub enum Advisory {
    CVE { y: u16, n: u64 },
}

lazy_static! {
    static ref CVESPEC: Regex = Regex::new(r"^CVE-(\d{4})-(\d+)$").unwrap();
}

#[derive(Debug, Error)]
pub enum AdvErr {
    #[error("Failed to parse CVE identifier `{}'", id)]
    ParseCVE { id: String },
}

impl FromStr for Advisory {
    type Err = AdvErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let id = s.to_owned();
        match CVESPEC.captures(s) {
            Some(cap) => Ok(Advisory::CVE {
                y: cap[1]
                    .parse::<u16>()
                    .map_err(|_| AdvErr::ParseCVE { id: id.clone() })?,
                n: cap[2]
                    .parse::<u64>()
                    .map_err(|_| AdvErr::ParseCVE { id: id.clone() })?,
            }),
            None => Err(AdvErr::ParseCVE { id }),
        }
    }
}

impl TryFrom<String> for Advisory {
    type Error = AdvErr;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        FromStr::from_str(&s)
    }
}

impl fmt::Display for Advisory {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            Advisory::CVE { y, n } => write!(f, "CVE-{}-{:04}", y, n),
        }
    }
}

// === Tests ===

#[cfg(test)]
mod test {
    use super::*;
    use assert_matches::assert_matches;

    fn cve(y: u16, n: u64) -> Advisory {
        Advisory::CVE { y, n }
    }

    #[test]
    fn fmt_cve() {
        assert_eq!(cve(2019, 544).to_string(), "CVE-2019-0544");
        assert_eq!(cve(2019, 3544).to_string(), "CVE-2019-3544");
        assert_eq!(cve(2019, 1003544).to_string(), "CVE-2019-1003544");
    }

    #[test]
    fn parse_cve() {
        assert_eq!(
            "CVE-2019-20484"
                .parse::<Advisory>()
                .expect("no parse error"),
            Advisory::CVE { y: 2019, n: 20484 }
        );
        assert_matches!("".parse::<Advisory>(), Err(AdvErr::ParseCVE { .. }));
        assert_matches!("foo".parse::<Advisory>(), Err(AdvErr::ParseCVE { .. }));
        assert_matches!("CVE-20".parse::<Advisory>(), Err(AdvErr::ParseCVE { .. }));
        assert_matches!("CVE-20-1".parse::<Advisory>(), Err(AdvErr::ParseCVE { .. }));
        assert_matches!(
            "CVE-2014-".parse::<Advisory>(),
            Err(AdvErr::ParseCVE { .. })
        );
    }
}
