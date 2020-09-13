use smol::fs;
use std::io::Result;

pub async fn read_cmdline(pid: u32) -> Result<String> {
    let path = format!("/proc/{}/cmdline", pid);
    let data = fs::read(path).await?;
    let raw_cmdline = String::from_utf8(data).unwrap();
    let cmdline = raw_cmdline.trim_end_matches('\0').replace("\0", " ");
    Ok(cmdline)
}
