//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
use crate::get_client;
use anyhow::{anyhow, Context, Result};
use oci_distribution::{secrets::RegistryAuth, Reference, RegistryOperation};
use serde_yaml::{self, Value};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::PathBuf;
use url::Url;

use base64::{engine::general_purpose, Engine};
use serde::{Deserialize, Serialize};

/// Info used to login into an OCI registry
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct LoginInfo {
    url: String,
    // auth with the format: base64Encode("username:password")
    auth: String,
}

impl LoginInfo {
    /// Create a `LoginInfo`
    /// url - The url to the registry
    /// user - username
    /// pwd - password
    pub fn new(url: &str, user: &str, pwd: &str) -> Self {
        Self {
            url: String::from(url),
            auth: general_purpose::STANDARD.encode(format!("{}:{}", user, pwd)),
        }
    }

    fn get_user_pwd(&self) -> Result<(String, String)> {
        let dec = general_purpose::STANDARD.decode(&self.auth)?;
        let Some(idx) = dec.iter().position(|x|*x==b':') else {
            return Err(anyhow!("auth info format incorrect"))
        };

        let (user, pwd) = dec.split_at(idx);
        Ok((
            String::from_utf8_lossy(user).to_string(),
            String::from_utf8_lossy(&pwd[1..]).to_string(),
        ))
    }
}

/// The AuthInfo
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthInfo(Vec<LoginInfo>);

impl AuthInfo {
    /// Get `AuthInfo` from the default cache file
    pub fn get(path: &PathBuf) -> Result<Self> {
        AuthInfo::read_from_file(&mut get_auth_save_file(path)?)
    }

    fn read_from_file(file: &mut File) -> Result<AuthInfo> {
        let mut data = vec![];
        file.read_to_end(&mut data)?;
        if data.is_empty() {
            return Ok(Self(vec![]));
        }
        // serde_json::from_slice(&data)?
        serde_json::from_slice(&data).context("Failed to deserialize auth config from file")
    }

    fn write_to_file(&self, file: &mut File) -> Result<()> {
        file.set_len(0)?;
        serde_json::to_writer(file, self).context("Failed to serialize auth config to file")?;
        Ok(())
    }

    /// return (username, password)
    fn get_auth_info_by_url(&self, url: &str) -> Result<(String, String)> {
        for i in self.0.iter() {
            if i.url == url {
                return i.get_user_pwd();
            }
        }
        Err(anyhow!("url have no login info"))
    }
    /// Set the login info
    pub fn set_login_info(&mut self, login_info: LoginInfo) {
        if let Some(idx) = self.0.iter().position(|x| x.url == login_info.url) {
            let _ = std::mem::replace(&mut self.0[idx], login_info);
        } else {
            self.0.push(login_info);
        }
    }
    /// Remove the login info
    pub fn remove_login_info(&mut self, url: &str) -> Result<()> {
        let Some(idx) = self.0.iter().position(|x|x.url==url) else {
            return Err(anyhow!("auth info of url: {} not found",url));
        };
        self.0.remove(idx);
        Ok(())
    }
}
/// Extract auth ingo from a URL
pub fn get_auth_info_by_url_with_path(url: &Url, path: &PathBuf) -> Result<(String, String)> {
    if !url.username().is_empty() {
        return Ok((
            url.username().into(),
            url.password().unwrap_or_default().into(),
        ));
    }
    let auth_info = AuthInfo::get(path)?;
    auth_info.get_auth_info_by_url(url.host_str().unwrap())
}

pub fn get_auth_info_by_url(url: &Url) -> Result<(String, String)> {
    if url.username().is_empty() {
        return Err(anyhow!("Url is empty"));
    }
    Ok((
        url.username().into(),
        url.password().unwrap_or_default().into(),
    ))
}

pub fn get_registry_auth(user: String, password: String) -> RegistryAuth {
    RegistryAuth::Basic(user, password)
}

fn get_auth_save_file(path: &PathBuf) -> Result<File> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&path)?)
}

#[cfg(test)]
mod test {
    use url::Url;

    use super::{AuthInfo, LoginInfo};

    const HOST1: &str = "http://127.0.0.1";
    const USERNAME1: &str = "username_test1";
    const PASSWORD1: &str = "password_test1";

    const HOST2: &str = "http://172.17.0.1";
    const USERNAME2: &str = "username_test2";
    const PASSWORD2: &str = "password_test2";

    #[test]
    fn test_auth() {
        let url1 = Url::parse(HOST1).unwrap();
        let url2 = Url::parse(HOST2).unwrap();
        let login1 = LoginInfo::new(url1.host_str().unwrap(), USERNAME1, PASSWORD1);
        let login2 = LoginInfo::new(url2.host_str().unwrap(), USERNAME2, PASSWORD2);
        let mut auth = AuthInfo(vec![]);

        auth.set_login_info(login1.clone());
        auth.set_login_info(login2.clone());

        assert_eq!(auth.0.len(), 2);
        assert_eq!(
            auth.get_auth_info_by_url(url2.host_str().unwrap()).unwrap(),
            login2.get_user_pwd().unwrap()
        );
        assert_eq!(
            auth.get_auth_info_by_url(url1.host_str().unwrap()).unwrap(),
            login1.get_user_pwd().unwrap()
        );

        auth.remove_login_info(url2.host_str().unwrap()).unwrap();

        assert_eq!(auth.0.len(), 1);

        assert_eq!(
            auth.get_auth_info_by_url(url1.host_str().unwrap()).unwrap(),
            login1.get_user_pwd().unwrap()
        );
        assert!(auth.get_auth_info_by_url(url2.host_str().unwrap()).is_err());
    }
}

pub fn get_gh_env_token() -> Result<(String, String)> {
    let gh_config_path = home::home_dir().unwrap().join(".config/gh/hosts.yml");
    if gh_config_path.exists() {
        let gh_config = fs::File::open(gh_config_path).unwrap();
        let config: Value = serde_yaml::from_reader(gh_config).unwrap();
        Ok((
            config["github.com"]["user"].as_str().unwrap().to_string(),
            config["github.com"]["oauth_token"]
                .as_str()
                .unwrap()
                .to_string(),
        ))
    } else {
        Err(anyhow!("Could not find gh config"))
    }
}

/// Login into an OCI registry
/// Will prompt and read username and password from stdin
pub async fn login(u: String, user: String, password: String, path: &PathBuf) -> Result<()> {
    let url = Url::parse(u.as_str())?;

    return login_registry(url, &user, &password, path).await;
}

async fn login_registry(url: Url, username: &str, token: &str, path: &PathBuf) -> Result<()> {
    let Some(host) = url.host_str() else {
        return Err(anyhow!("url format incorrect"))
    };
    let mut auth_info = AuthInfo::get(path)?;
    let login_info = LoginInfo::new(host, username, token);

    v2_login(&url, &login_info).await?;
    auth_info.set_login_info(login_info);
    auth_info.write_to_file(&mut get_auth_save_file(path)?)?;
    println!("Login success");
    Ok(())
}

/// Login into an OCI registry
/// Will use username and password in LoginInfo
async fn v2_login(url: &Url, login_info: &LoginInfo) -> Result<()> {
    let (username, password) = login_info.get_user_pwd()?;
    let mut client = get_client(url)?;
    let reference = Reference::with_tag(url.host_str().unwrap().into(), "/".into(), "".into());
    client
        .auth(
            &reference,
            &RegistryAuth::Basic(username, password),
            RegistryOperation::Push,
        )
        .await
        .map_err(|e| e.into())
}
