use anyhow::{Context, Result};
use smol::fs;

pub async fn read_cmdline(pid: u32) -> Result<String> {
    let path = format!("/proc/{}/cmdline", pid);
    let data = fs::read(&path)
        .await
        .with_context(|| format!("cannot read {}", &path))?;
    let raw_cmdline =
        String::from_utf8(data).with_context(|| format!("invalid utf8 contained in {}", &path))?;
    let cmdline = raw_cmdline.trim_end_matches('\0').replace("\0", " ");
    Ok(cmdline)
}
