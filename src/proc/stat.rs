use crate::regex_util::CapturesAdapter;
use anyhow::{Context, Result};
use regex::Regex;
use smol::fs::File;
use smol::io::BufReader;
use smol::prelude::{AsyncBufReadExt, AsyncReadExt, StreamExt};

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Stat {
    pub comm: String,
    pub state: String,
    pub ppid: u32,
    pub pgrp: u32,
    pub session: u32,
    pub tty_nr: i32,
    pub tpgid: i32,
    pub utime: u64,
    pub stime: u64,
    pub nice: i64,
    pub num_threads: i32,
    pub start_time: u64,
}

pub async fn load_stat(pid: u32) -> Result<Stat> {
    let path = format!("/proc/{}/stat", pid);
    let file = File::open(&path)
        .await
        .with_context(|| format!("cannot open {}", &path))?;
    read_stat(BufReader::new(file))
        .await
        .with_context(|| format!("read error for {}", &path))
}

async fn read_stat<R: AsyncReadExt + Unpin>(mut reader: BufReader<R>) -> Result<Stat> {
    lazy_static! {
        // https://elixir.bootlin.com/linux/latest/C/ident/do_task_stat
        static ref STAT_RE: Regex = Regex::new(r"^(?P<pid>\d+) \((?P<comm>.+?)\) (?P<state>.) (?P<ppid>\d+) (?P<pgrp>\d+) (?P<session>\d+) (?P<tty_nr>\d+) (?P<tpgid>-?\d+) (?P<flags>-?\d+) (?P<minflt>\d+) (?P<cminflt>\d+) (?P<majflt>\d+) (?P<cmajflt>\d+) (?P<utime>\d+) (?P<stime>\d+) (?P<cutime>-?\d+) (?P<cstime>-?\d+) (?P<priority>-?\d+) (?P<nice>-?\d+) (?P<num_threads>-?\d+) (?P<itrealvalue>-?\d+) (?P<starttime>\d+)").unwrap();
    }

    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .await
        .with_context(|| "cannot read /proc/[pid]/stat file")?;
    let text = std::str::from_utf8(&buf)
        .with_context(|| "invalid utf8 character in /proc/[pid]/stat file")?;
    let caps = STAT_RE
        .captures(text)
        .with_context(|| "regex match failed")?;
    let caps = CapturesAdapter::new(caps);
    let comm = caps.string_by_name("comm");
    let state = caps.string_by_name("state");
    let ppid = caps.int_by_name::<u32>("ppid")?;
    let pgrp = caps.int_by_name::<u32>("pgrp")?;
    let session = caps.int_by_name::<u32>("session")?;
    let tty_nr = caps.int_by_name::<i32>("tty_nr")?;
    let tpgid = caps.int_by_name::<i32>("tpgid")?;
    let utime = caps.int_by_name::<u64>("utime")?;
    let stime = caps.int_by_name::<u64>("stime")?;
    let nice = caps.int_by_name::<i64>("nice")?;
    let num_threads = caps.int_by_name::<i32>("num_threads")?;
    let start_time = caps.int_by_name::<u64>("starttime")?;
    Ok(Stat {
        comm,
        state,
        ppid,
        pgrp,
        session,
        tty_nr,
        tpgid,
        utime,
        stime,
        nice,
        num_threads,
        start_time,
    })
}

pub async fn get_btime() -> Result<u64> {
    const PATH: &str = "/proc/stat";
    let file = File::open(PATH).await.with_context(|| format!("cannot open {}", PATH))?;
    let reader = BufReader::new(file);

    lazy_static! {
        static ref BTIME_RE: Regex = Regex::new(r"^btime[\t ]+(\d+)").unwrap();
    }
    let mut lines = reader.lines();
    let mut btime = 0u64;
    while let Some(line) = lines.next().await {
        if let Some(caps) = BTIME_RE.captures(&line?) {
            let caps = CapturesAdapter::new(caps);
            btime = caps.int_by_index::<u64>(1)?;
        }
    }
    Ok(btime)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_read_stat() {
        let input = b"12 (migration/0) S 2 0 0 0 -1 69238848 0 0 0 0 1 0 0 0 -100 0 1 0 15 0 0 18446744073709551615 0 0 0 0 0 0 0 2147483647 0 0 0 0 17 0 99 1 0 0 0 0 0 0 0 0 0 0 0";
        let reader = BufReader::new(&input[..]);
        let wanted = Stat {
            comm: String::from("migration/0"),
            state: String::from("S"),
            ppid: 2,
            pgrp: 0,
            session: 0,
            tty_nr: 0,
            tpgid: -1,
            utime: 1,
            stime: 0,
            nice: 0,
            num_threads: 1,
            start_time: 15,
        };
        let stat = smol::block_on(async { read_stat(reader).await.unwrap() });
        assert_eq!(stat, wanted);
    }
}
