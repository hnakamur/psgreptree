use regex::Regex;
use smol::fs::File;
use smol::io::BufReader;
use smol::prelude::AsyncReadExt;
use std::io::Result;

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
    let file = File::open(path).await?;
    read_stat(BufReader::new(file)).await
}

async fn read_stat<R: AsyncReadExt + Unpin>(mut reader: BufReader<R>) -> Result<Stat> {
    lazy_static! {
        // https://elixir.bootlin.com/linux/latest/C/ident/do_task_stat
        static ref STAT_RE: Regex = Regex::new(r"^(?P<pid>\d+) \((?P<comm>.+?)\) (?P<state>.) (?P<ppid>\d+) (?P<pgrp>\d+) (?P<session>\d+) (?P<tty_nr>\d+) (?P<tpgid>-?\d+) (?P<flags>-?\d+) (?P<minflt>\d+) (?P<cminflt>\d+) (?P<majflt>\d+) (?P<cmajflt>\d+) (?P<utime>\d+) (?P<stime>\d+) (?P<cutime>-?\d+) (?P<cstime>-?\d+) (?P<priority>-?\d+) (?P<nice>-?\d+) (?P<num_threads>-?\d+) (?P<itrealvalue>-?\d+) (?P<starttime>\d+) (?P<vsize>\d+) (?P<rss>\d+)").unwrap();
    }

    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).await?;
    let text = std::str::from_utf8(&buf).unwrap();
    let cap = STAT_RE.captures(text).unwrap();
    let comm = cap.name("comm").unwrap().as_str().to_string();
    let state = cap.name("state").unwrap().as_str().to_string();
    let ppid = cap.name("ppid").unwrap().as_str().parse::<u32>().unwrap();
    let pgrp = cap.name("pgrp").unwrap().as_str().parse::<u32>().unwrap();
    let session = cap
        .name("session")
        .unwrap()
        .as_str()
        .parse::<u32>()
        .unwrap();
    let tty_nr = cap.name("tty_nr").unwrap().as_str().parse::<i32>().unwrap();
    let tpgid = cap.name("tpgid").unwrap().as_str().parse::<i32>().unwrap();
    let utime = cap.name("utime").unwrap().as_str().parse::<u64>().unwrap();
    let stime = cap.name("stime").unwrap().as_str().parse::<u64>().unwrap();
    let nice = cap.name("nice").unwrap().as_str().parse::<i64>().unwrap();
    let num_threads = cap
        .name("num_threads")
        .unwrap()
        .as_str()
        .parse::<i32>()
        .unwrap();
    let start_time = cap
        .name("starttime")
        .unwrap()
        .as_str()
        .parse::<u64>()
        .unwrap();
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

mod test {
    use super::*;

    #[test]
    fn test_read_stat() {
        let mut bytes = b"12 (migration/0) S 2 0 0 0 -1 69238848 0 0 0 0 1 0 0 0 -100 0 1 0 15 0 0 18446744073709551615 0 0 0 0 0 0 0 2147483647 0 0 0 0 17 0 99 1 0 0 0 0 0 0 0 0 0 0 0"
            .to_vec();
        let cursor = smol::io::Cursor::new(&mut bytes);
        let reader = BufReader::new(cursor);
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
