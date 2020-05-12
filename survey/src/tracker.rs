/// Interface to issue trackers.
///
/// Implements currently only GitHub issues.
use crate::ticket::Ticket;

use clap::{crate_name, crate_version};
use futures::compat::*;
use futures::executor::block_on;
use futures::prelude::*;
use hubcaps::comments::{Comment, CommentOptions};
use hubcaps::issues::{Issue, IssueOptions};
use hubcaps::Credentials;
use hyper::client::HttpConnector;
use hyper_tls::HttpsConnector;
use std::str::FromStr;
use thiserror::Error;

type Github = hubcaps::Github<HttpsConnector<HttpConnector>>;
type Repository = hubcaps::repositories::Repository<HttpsConnector<HttpConnector>>;
type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("GitHub error while {act}: {e}")]
    GitHub { act: String, e: String },
    #[error("Repository specification must be in the format <OWNER>/<REPO>")]
    RepoFormat,
}

#[derive(Debug, Clone, PartialEq)]
struct RepoSpec {
    owner: String,
    repo: String,
}

impl RepoSpec {
    #[allow(unused)]
    fn new<S: Into<String>, T: Into<String>>(owner: S, repo: T) -> Self {
        Self {
            owner: owner.into(),
            repo: repo.into(),
        }
    }
}

impl FromStr for RepoSpec {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut elem = s.split('/');
        let owner = elem.next().ok_or(Error::RepoFormat)?.to_owned();
        let repo = elem.next().ok_or(Error::RepoFormat)?.to_owned();
        if owner.is_empty() || repo.is_empty() || elem.next().is_some() {
            Err(Error::RepoFormat)
        } else {
            Ok(Self { owner, repo })
        }
    }
}

pub struct Tracker {
    repo: RepoSpec,
    conn: Github,
    repo_hdl: Repository,
}

impl Tracker {
    pub fn connect_github(token: String, repo_spec: &str) -> Result<Self> {
        let conn = Github::new(
            concat!(crate_name!(), "/", crate_version!()),
            Credentials::Token(token),
        );
        let repo: RepoSpec = repo_spec.parse()?;
        let repo_hdl = conn.repo(&repo.owner, &repo.repo);
        Ok(Self {
            repo,
            conn,
            repo_hdl,
        })
    }

    async fn gh_create(&self, tkt: &Ticket) -> Result<Issue> {
        Compat01As03::new(self.repo_hdl.issues().create(&IssueOptions {
            title: tkt.summary(),
            body: Some(tkt.body()),
            assignee: None,
            milestone: None,
            labels: vec!["1.severity: security".to_owned()],
        }))
        .await
        .map_err(|e| Error::GitHub {
            act: format!("creating issue for {}", tkt.name()),
            e: e.to_string(),
        })
    }

    async fn gh_related(&self, tkt: &Ticket) -> Result<Vec<String>> {
        let query = format!(
            "\
repo:{}/{} is:open label:\"1.severity: security\" in:title \"Vulnerability roundup \" \" {}: \"",
            self.repo.owner,
            self.repo.repo,
            tkt.name()
        );
        Compat01As03::new(
            self.conn
                .search()
                .issues()
                .iter(&query, &Default::default()),
        )
        .map(|res| res.map(|rel| format!("#{}", rel.number)))
        .try_collect()
        .map_err(|e| Error::GitHub {
            act: format!("searching related to {}", tkt.name()),
            e: e.to_string(),
        })
        .await
    }

    async fn gh_comment(&self, number: u64, related: &[String]) -> Result<Comment> {
        Compat01As03::new(
            self.repo_hdl
                .issues()
                .get(number)
                .comments()
                .create(&CommentOptions {
                    body: format!("See also: {}", related.join(", ")),
                }),
        )
        .map_err(|e| Error::GitHub {
            act: format!("commenting on #{}", number),
            e: e.to_string(),
        })
        .await
    }

    async fn create_issue_async(&self, tkt: &Ticket) -> Result<(u64, String)> {
        let (iss, related) = future::join(self.gh_create(tkt), self.gh_related(tkt)).await;
        let iss = iss?;
        let related = related?;
        if !related.is_empty() {
            self.gh_comment(iss.number, &related).await?;
        }
        Ok((iss.number, iss.html_url))
    }

    pub fn create_issue(&self, tkt: &Ticket) -> Result<(u64, String)> {
        block_on(self.create_issue_async(tkt))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn repospec_parse() {
        assert_eq!(RepoSpec::new("foo", "bar"), "foo/bar".parse().unwrap());
        assert!("".parse::<RepoSpec>().is_err());
        assert!("/".parse::<RepoSpec>().is_err());
        assert!("/foo".parse::<RepoSpec>().is_err());
        assert!("foo/".parse::<RepoSpec>().is_err());
        assert!("foo/bar/".parse::<RepoSpec>().is_err());
    }
}
