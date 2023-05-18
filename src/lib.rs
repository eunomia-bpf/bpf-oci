//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
pub mod auth;
mod wasm;

use anyhow::{anyhow, Result};
use std::path::Path;

use oci_distribution::{
    client::{ClientConfig, ClientProtocol},
    Client,
};

use tokio::fs::{File, OpenOptions};
use tokio::io;
use url::Url;
/// Ex-export some helper functions from wasm module
pub use wasm::wasm_pull;
pub use wasm::wasm_push;
pub use wasm::{PullArgs, PushArgs};

/// A helper function to get the default port for http or https
fn default_schema_port(schema: &str) -> Result<u16> {
    match schema {
        "http" => Ok(80),
        "https" => Ok(443),
        _ => Err(anyhow!("unknown schema {}", schema)),
    }
}

/// Create a HTTP client for the given url
pub fn get_client(url: &Url) -> Result<Client> {
    let protocol = match url.scheme() {
        "http" => Ok(ClientProtocol::Http),
        "https" => Ok(ClientProtocol::Https),
        _ => Err(anyhow!("unsupported schema {}", url.scheme())),
    }?;

    Ok(Client::new(ClientConfig {
        protocol,
        ..Default::default()
    }))
}

/// Push an image to the OCI registry
pub async fn push(args: PushArgs) -> Result<()> {
    wasm_push(args.file, args.image_url, args.username, args.password).await?;
    Ok(())
}

/// Pull an image from the registry
pub async fn pull(args: PullArgs) -> Result<()> {
    let path = Path::new(&args.write_file);
    let mut file = if path.is_file() {
        OpenOptions::new()
            .write(true)
            .open(&args.write_file)
            .await?
    } else {
        File::create(&args.write_file).await?
    };
    let data = wasm_pull(args.image_url.as_str(), args.username, args.password).await?;
    io::copy(&mut &data[..], &mut file).await?;
    Ok(())
}
