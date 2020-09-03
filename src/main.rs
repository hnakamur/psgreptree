#[macro_use]
extern crate lazy_static;

use async_fs::read_dir;
use futures_lite::stream::StreamExt;
use regex::Regex;
use std::io;

fn main() {
    std::env::set_var("SMOL_THREADS", format!("{}", num_cpus::get()));

    smol::block_on(async {
        psgrep().await.unwrap();
    });
}

async fn psgrep() -> io::Result<()> {
    lazy_static! {
        static ref PID_RE: Regex = Regex::new(r"^\d+$").unwrap();
    }

    let mut entries = read_dir("/proc").await?;
    while let Some(res) = entries.next().await {
        let entry = res?;
        if PID_RE.is_match(entry.file_name().to_str().unwrap()) {
            println!("path={:?}", entry.path());
        }
    }
    Ok(())
}
