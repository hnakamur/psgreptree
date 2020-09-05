#[macro_use]
extern crate lazy_static;

use async_fs::{read_dir, DirEntry};
use clap::{App, Arg};
use futures_lite::future;
use futures_lite::stream::{self, StreamExt};
use regex::Regex;
use std::collections::HashMap;
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
        let mut filtered = filter_procs(&procs, pattern.unwrap());
        add_descendants(&mut filtered, &procs);
        println!("filtered={:?}", filtered);

        // fill_cmdline_for_matches(&mut procs, pattern.unwrap())
        //     .await
        //     .unwrap();
        // mark_wanted(&mut procs);
        // println!("procs={:?}", procs);
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

async fn all_procs(all_pids: Vec<i32>) -> io::Result<HashMap<i32, Process>> {
    let mut pids = HashMap::new();
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

fn filter_procs(procs: &HashMap<i32, Process>, pattern: &str) -> HashMap<i32, Process> {
    let re = Regex::new(pattern).expect("valid regular expression");
    let mut filtered = HashMap::new();
    for (pid, proc) in procs.iter() {
        if re.is_match(&proc.cmdline) {
            filtered.insert(*pid, proc.clone());
        }
    }
    filtered
}

fn add_descendants(filtered: &mut HashMap<i32, Process>, all_procs: &HashMap<i32, Process>) {
    let mut pid_stack = Vec::new();

    'outer: for (pid, mut proc) in all_procs.iter() {
        if filtered.contains_key(pid) {
            continue;
        }

        while proc.ppid != 0 {
            if filtered.contains_key(&proc.ppid) {
                filtered.insert(*pid, proc.clone());
                for pid in pid_stack.drain(..) {
                    if !filtered.contains_key(pid) {
                        filtered.insert(*pid, all_procs.get(pid).unwrap().clone());
                    }
                }
                continue 'outer;
            }
            if let Some(proc2) = all_procs.get(&proc.ppid) {
                pid_stack.push(&proc.pid);
                proc = proc2;
            }
        }
        pid_stack.clear();
    }
}
