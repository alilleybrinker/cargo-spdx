//! Functions for getting git metadata.

use anyhow::Result;

/// Get the current Git user.
///
/// This requires that the name is specified, but permits the
/// email to be missing.
pub fn get_current_user() -> Result<User> {
    let git_config = git2::Config::open_default()?.snapshot()?;
    let name = git_config.get_str("user.name")?.to_owned();
    let email = git_config.get_str("user.email").ok().map(ToOwned::to_owned);
    Ok(User { name, email })
}

/// A user pulled from the Git config.
#[derive(Debug)]
pub struct User {
    /// The user's name.
    pub name: String,
    /// The user's email, if specified.
    pub email: Option<String>,
}
