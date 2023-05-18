extern crate anyhow;
extern crate simoci;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    simoci::wasm_push(
        "test.wasm".to_string(),
        "https://ghcr.io/xxx/xxx".to_string(),
        "username".to_string(),
        "some_token".to_string(),
    )
    .await?;
    Ok(())
}
