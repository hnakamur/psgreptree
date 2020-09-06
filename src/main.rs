#[macro_use]
extern crate lazy_static;

use async_fs::{read_dir, DirEntry};
use clap::{App, Arg};
use futures_lite::future;
use futures_lite::stream::{self, StreamExt};
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io;
use std::process;
use std::str;

#[derive(Debug, Clone)]
struct Process {
    pid: u32,
    ppid: u32,
    cmdline: String,
}

#[derive(Debug, Clone)]
struct ProcessForestNode {
    process: Process,
    child_pids: Vec<u32>,
}

#[derive(Debug, Clone)]
struct ProcessForest {
    roots: BTreeSet<u32>,
    nodes: BTreeMap<u32, ProcessForestNode>,
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
        // println!("wanted_procs={:?}", wanted_procs);
        let proc_forest = build_process_forest(wanted_procs);
        println!("proc_forest={:?}", proc_forest);
    });
}

async fn all_pids() -> io::Result<Vec<u32>> {
    let mut pids = Vec::new();
    let mut entries = read_dir("/proc").await?;
    while let Some(res) = entries.next().await {
        let entry = res?;
        if is_pid_entry(&entry) {
            pids.push(entry.file_name().to_str().unwrap().parse::<u32>().unwrap());
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

async fn all_procs(all_pids: Vec<u32>) -> io::Result<BTreeMap<u32, Process>> {
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

async fn get_ppid(pid: u32) -> io::Result<u32> {
    lazy_static! {
        static ref PPID_RE: Regex = Regex::new(r"\) . (\d+)").unwrap();
    }

    let path = format!("/proc/{}/stat", pid);
    let data = async_fs::read(path).await?;
    let text = str::from_utf8(&data).unwrap();
    let caps = PPID_RE.captures(text).unwrap();
    let ppid = caps.get(1).unwrap().as_str().parse::<u32>().unwrap();
    Ok(ppid)
}

async fn get_cmdline(pid: u32) -> io::Result<String> {
    let path = format!("/proc/{}/cmdline", pid);
    let data = async_fs::read(path).await?;
    let raw_cmdline = String::from_utf8(data).unwrap();
    let cmdline = raw_cmdline.trim_end_matches('\0').replace("\0", " ");
    Ok(cmdline)
}

fn match_cmdline(procs: &BTreeMap<u32, Process>, pattern: &str) -> BTreeSet<u32> {
    let mut pids = BTreeSet::new();
    let re = Regex::new(pattern).expect("valid regular expression");
    let my_pid = process::id();
    for (pid, proc) in procs.iter() {
        if re.is_match(&proc.cmdline) && *pid != my_pid {
            pids.insert(*pid);
        }
    }
    pids
}

fn get_matched_and_descendants(
    procs: &BTreeMap<u32, Process>,
    matched_pids: &BTreeSet<u32>,
) -> BTreeMap<u32, Process> {
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

fn build_process_forest(procs: BTreeMap<u32, Process>) -> ProcessForest {
    let mut roots = BTreeSet::new();
    let mut nodes = BTreeMap::new();
    for (pid, proc) in procs.iter() {
        if procs.contains_key(&proc.ppid) {
            let parent_node = nodes.entry(proc.ppid).or_insert(ProcessForestNode {
                process: procs.get(&proc.ppid).unwrap().clone(),
                child_pids: Vec::new(),
            });
            parent_node.child_pids.push(*pid);
        } else {
            roots.insert(*pid);
        }

        if !nodes.contains_key(pid) {
            nodes.insert(
                *pid,
                ProcessForestNode {
                    process: proc.clone(),
                    child_pids: Vec::new(),
                },
            );
        }
    }
    ProcessForest { roots, nodes }
}
