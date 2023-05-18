//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
use std::path::Path;

use anyhow::anyhow;
use anyhow::Result;
use log::info;
use std::collections::HashMap;
use tokio::{fs::File, io::AsyncReadExt};
use url::Url;
use wasmparser;

use oci_distribution::{
    client::{Config, ImageLayer},
    manifest,
    secrets::RegistryAuth,
    Client, Reference,
};

use super::{auth, default_schema_port, get_client};

/// Parse the URL, return things that will be used for pushing / pulling
/// returns (..., repo_url_strip_auth_info)
pub fn parse_img_url(url: &str) -> anyhow::Result<(Client, Reference, String)> {
    let img_url = Url::parse(url)?;
    let client = get_client(&img_url)?;
    let host = img_url
        .host()
        .ok_or_else(|| anyhow!("invalid url: {}", url))?;
    let port = default_schema_port(img_url.scheme())?;
    let repo_url = format!("{}:{}{}", host, port, img_url.path());

    let reference = repo_url.parse::<Reference>()?;

    Ok((client, reference, repo_url))
}

/// Push an image
pub async fn wasm_push(
    file: String,
    img_url: String,
    username: String,
    password: String,
) -> Result<()> {
    let path = Path::new(&file);

    if !path.is_file() {
        return Err(anyhow!("{} is not a regular file", file));
    }

    let mut module = Vec::new();
    let mut file = File::open(&path).await?;
    file.read_to_end(&mut module).await?;

    wasmparser::validate(&module)?;

    let (mut client, reference, _) = parse_img_url(&img_url)?;
    let auth = auth::get_registry_auth(username, password);
    push_wasm_to_registry(&mut client, &auth, &reference, module, None).await?;
    Ok(())
}

/// Pull an image
pub async fn wasm_pull(img: &str, username: String, password: String) -> Result<Vec<u8>> {
    let (mut client, reference, repo_url) = parse_img_url(img)?;
    info!("pulling from {}", repo_url);

    let auth = auth::get_registry_auth(username, password);
    let img_content = pull_wasm_from_registry(&mut client, &auth, &reference).await?;
    info!(
        "successful pull {} bytes from {}",
        img_content.len(),
        repo_url
    );
    // check wasm valid
    wasmparser::validate(&img_content)?;
    Ok(img_content)
}
/// Configuration for a pulling process
pub struct PullArgs {
    /// wasm image path to write
    pub write_file: String,
    /// wasm image url
    pub image_url: String,
    /// oci username
    pub username: String,
    /// oci password
    pub password: String,
}

pub(super) async fn pull_wasm_from_registry(
    client: &mut Client,
    auth: &RegistryAuth,
    reference: &Reference,
) -> Result<Vec<u8>> {
    if let Some(img_data) = client
        .pull(reference, auth, vec![manifest::WASM_LAYER_MEDIA_TYPE])
        .await?
        .layers
        .into_iter()
        .next()
        .map(|layer| layer.data)
    {
        Ok(img_data)
    } else {
        let repo_url = format!(
            "{}/{}:{}",
            reference.registry(),
            reference.repository(),
            reference.tag().unwrap_or("latest"),
        );
        Err(anyhow!("no data found in url: {}", repo_url))
    }
}

/// Configuration for a pushing process
pub struct PushArgs {
    /// Local file path
    pub file: String,
    /// URL to push
    pub image_url: String,
    /// username
    pub username: String,
    /// password
    pub password: String,
}
// return the manifest url
pub async fn push_wasm_to_registry(
    client: &mut Client,
    auth: &RegistryAuth,
    reference: &Reference,
    module: Vec<u8>,
    annotations: Option<HashMap<String, String>>,
) -> Result<String> {
    let layers = vec![ImageLayer::new(
        module,
        manifest::WASM_LAYER_MEDIA_TYPE.to_string(),
        None,
    )];

    let config = Config {
        data: b"{}".to_vec(),
        media_type: manifest::WASM_CONFIG_MEDIA_TYPE.to_string(),
        annotations: None,
    };

    let image_manifest = manifest::OciImageManifest::build(&layers, &config, annotations);

    let resp = client
        .push(reference, &layers, config, auth, Some(image_manifest))
        .await?;

    Ok(resp.manifest_url)
}
