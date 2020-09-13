use crate::regex_util::CapturesAdapter;
use nix::unistd::Uid;
use regex::Regex;
use smol::fs::File;
use smol::io::BufReader;
use smol::prelude::{AsyncBufReadExt, AsyncReadExt, StreamExt};
use std::io::Result;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Status {
    pub euid: Uid,
    pub vm_size: u64,
    pub vm_lock: u64,
    pub vm_rss: u64,
}

pub async fn load_status(pid: u32) -> Result<Status> {
    let path = format!("/proc/{}/status", pid);
    let file = File::open(path).await?;
    read_status(BufReader::new(file)).await
}

async fn read_status<R: AsyncReadExt + Unpin>(reader: BufReader<R>) -> Result<Status> {
    lazy_static! {
        static ref KEY_VAL_RE: Regex = Regex::new(r"^(.*?):[\t ]*(.+)").unwrap();
        static ref EUID_RE: Regex = Regex::new(r"^\d+\t(\d+)").unwrap();
        static ref KB_RE: Regex = Regex::new(r"^(\d+)").unwrap();
    }

    let mut euid: Uid = Uid::from_raw(0);
    let mut vm_size = 0u64;
    let mut vm_lock = 0u64;
    let mut vm_rss = 0u64;
    let mut lines = reader.lines();
    while let Some(line) = lines.next().await {
        let line = line.unwrap();
        if let Some(caps) = KEY_VAL_RE.captures(&line) {
            let caps = CapturesAdapter::new(caps);
            let key = caps.str_by_index(1);
            let value = caps.str_by_index(2);
            match key {
                "Uid" => {
                    let caps = CapturesAdapter::new(EUID_RE.captures(value).unwrap());
                    euid = Uid::from_raw(caps.int_by_index::<u32>(1).unwrap());
                }
                "VmSize" => {
                    let caps = CapturesAdapter::new(KB_RE.captures(value).unwrap());
                    vm_size = caps.int_by_index::<u64>(1).unwrap();
                }
                "VmLck" => {
                    let caps =  CapturesAdapter::new(KB_RE.captures(value).unwrap());
                    vm_lock = caps.int_by_index::<u64>(1).unwrap()
                }
                "VmRSS" => {
                    let caps = CapturesAdapter::new(KB_RE.captures(value).unwrap());
                    vm_rss = caps.int_by_index::<u64>(1).unwrap();
                }
                _ => {}
            }
        }
    }
    Ok(Status {
        euid,
        vm_size,
        vm_lock,
        vm_rss,
    })
}
