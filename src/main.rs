#[macro_use]
extern crate lazy_static;

use async_fs::{read_dir, DirEntry};
use clap::{App, Arg};
use futures_lite::future;
use futures_lite::stream::{self, StreamExt};
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io;
use std::str;

#[derive(Debug, Clone)]
struct Process {
    pid: i32,
    ppid: i32,
    cmdline: String,
}

fn main() {
    let matches = App::new("psgreptree")
        .version("0.1.0")
        .author("Kevin K. <kbknapp@gmail.com>")
        .about("Does awesome things")
        .arg(
            Arg::with_name("pattern")
                .short("r")
                .long("pattern")
                .value_name("REGEX")
                .help("Sets a regular expression to match process command lines")
                .takes_value(true),
        )
        .get_matches();
    let pattern = matches.value_of("pattern");
    println!("pattern={:?}", pattern);

    std::env::set_var("SMOL_THREADS", format!("{}", num_cpus::get()));

    smol::block_on(async {
        let pids = all_pids().await.unwrap();
        let procs = all_procs(pids).await.unwrap();
        let matched_pids = match_cmdline(&procs, pattern.unwrap());
        let wanted_procs = get_matched_and_descendants(&procs, &matched_pids);
        println!("wanted_procs={:?}", wanted_procs);
    });
}

async fn all_pids() -> io::Result<Vec<i32>> {
    let mut pids = Vec::new();
    let mut entries = read_dir("/proc").await?;
    while let Some(res) = entries.next().await {
        let entry = res?;
        if is_pid_entry(&entry) {
            pids.push(entry.file_name().to_str().unwrap().parse::<i32>().unwrap());
        }
    }
    Ok(pids)
}

fn is_pid_entry(entry: &DirEntry) -> bool {
    lazy_static! {
        static ref PID_RE: Regex = Regex::new(r"^\d+$").unwrap();
    }
    PID_RE.is_match(entry.file_name().to_str().unwrap())
}

async fn all_procs(all_pids: Vec<i32>) -> io::Result<BTreeMap<i32, Process>> {
    let mut pids = BTreeMap::new();
    let mut s = stream::iter(all_pids);
    while let Some(pid) = s.next().await {
        match future::zip(get_ppid(pid), get_cmdline(pid)).await {
            (Ok(ppid), Ok(cmdline)) => pids.insert(pid, Process { pid, ppid, cmdline }),
            (Err(e), _) => return Err(e),
            (_, Err(e)) => return Err(e),
        };
    }
    Ok(pids)
}

async fn get_ppid(pid: i32) -> io::Result<i32> {
    lazy_static! {
        static ref PPID_RE: Regex = Regex::new(r"\) . (\d+)").unwrap();
    }

    let path = format!("/proc/{}/stat", pid);
    let data = async_fs::read(path).await?;
    let text = str::from_utf8(&data).unwrap();
    let caps = PPID_RE.captures(text).unwrap();
    let ppid = caps.get(1).unwrap().as_str().parse::<i32>().unwrap();
    Ok(ppid)
}

async fn get_cmdline(pid: i32) -> io::Result<String> {
    let path = format!("/proc/{}/cmdline", pid);
    let data = async_fs::read(path).await?;
    let raw_cmdline = String::from_utf8(data).unwrap();
    let cmdline = raw_cmdline.trim_end_matches('\0').replace("\0", " ");
    Ok(cmdline)
}

fn match_cmdline(procs: &BTreeMap<i32, Process>, pattern: &str) -> BTreeSet<i32> {
    let mut pids = BTreeSet::new();
    let re = Regex::new(pattern).expect("valid regular expression");
    for (pid, proc) in procs.iter() {
        if re.is_match(&proc.cmdline) {
            pids.insert(*pid);
        }
    }
    pids
}

fn get_matched_and_descendants(procs: &BTreeMap<i32, Process>, matched_pids: &BTreeSet<i32>) -> BTreeMap<i32, Process> {
    let mut marks = HashMap::new();
    for pid in matched_pids.iter() {
        marks.insert(*pid, true);
    }

    let mut descendants = Vec::new();
    for (pid, mut proc) in procs.iter() {
        if marks.get(pid).is_some() {
            continue;
        }

        loop {
            let wanted = if proc.ppid == 0 {
                Some(false)
            } else if let Some(wanted) = marks.get(&proc.ppid) {
                Some(*wanted)
            } else {
                None
            };
            if let Some(wanted) = wanted {
                marks.insert(*pid, wanted);
                for pid in descendants.drain(..) {
                    marks.insert(pid, wanted);
                }
                break;
            } else {
                descendants.push(*pid);
                proc = procs.get(&proc.ppid).unwrap();
            }
        }
    }

    let mut wanted_procs = BTreeMap::new();
    for (pid, wanted) in marks.iter() {
        if *wanted {
            wanted_procs.insert(*pid, procs.get(pid).unwrap().clone());
        }
    }
    wanted_procs
}
