#![feature(map_first_last)]
use std::collections::BTreeMap;

#[macro_use]
extern crate lazy_static;

use async_fs::{read_dir, DirEntry};
use clap::{App, Arg};
use futures_lite::future;
use futures_lite::stream::{self, StreamExt};
use regex::Regex;
use std::cmp;
use std::collections::{BTreeSet, HashMap};
use std::fmt;
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

impl ProcessForest {
    fn pid_column_width(&self) -> usize {
        if let Some((pid, _)) = self.nodes.last_key_value() {
            column_width_for_u32(*pid)
        } else {
            0
        }
    }
}

impl fmt::Display for ProcessForest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut records = Vec::new();
        for pid in self.roots.iter() {
            print_forest_helper(&self, *pid, vec![], &mut records);
        }
        pad_columns(&mut records);
        for record in records {
            writeln!(f, "{} {}", record.pid, record.cmdline)?;
        }
        Ok(())
    }
}

struct OutputLineRecord {
    pid: String,
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
        // println!("wanted_procs={:?}", wanted_procs);
        let proc_forest = build_process_forest(wanted_procs);
        println!("proc_forest=\n{}", proc_forest);
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

fn column_width_for_u32(n: u32) -> usize {
    let mut width = 1;
    let mut n = n / 10;
    while n > 0 {
        width += 1;
        n /= 10;
    }
    width
}

fn print_forest_helper(f: &ProcessForest, pid: u32, last_child: Vec<bool>, records: &mut Vec<OutputLineRecord>) {
    let node = f.nodes.get(&pid).unwrap();
    records.push(OutputLineRecord{
        pid: format!("{}", pid),
        cmdline: format!("{}{}", last_child_to_indent(&last_child), node.process.cmdline),
    });
    let mut i = 0;
    while i < node.child_pids.len() {
        let child_pid = node.child_pids[i];
        let mut last_child2 = last_child.clone();
        last_child2.push(i == node.child_pids.len() - 1);
        print_forest_helper(f, child_pid, last_child2, records);
        i += 1;
    }
}

fn last_child_to_indent(last_child: &[bool]) -> String {
    let mut indent = String::new();
    let mut i = 0;
    while i < last_child.len() {
        indent.push_str(if i == last_child.len() - 1 {
            " \\_ "
        } else if last_child[i] {
            "    "
        } else {
            " |  "
        });
        i += 1;
    }
    indent
}

fn get_max_pid_column_width(records: &Vec<OutputLineRecord>) -> usize {
    records.iter().fold(0, |acc, x| cmp::max(acc, x.pid.len()))
}

fn pad_columns(records: &mut Vec<OutputLineRecord>) {
    let width = get_max_pid_column_width(&records);
    for record in records {
        record.pid = format!("{:>prec$}", record.pid, prec = width);
    }
}

mod test {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn test_column_width_for_u32() {
        assert_eq!(column_width_for_u32(0), 1);
        assert_eq!(column_width_for_u32(1), 1);
        assert_eq!(column_width_for_u32(9), 1);
        assert_eq!(column_width_for_u32(10), 2);
        assert_eq!(column_width_for_u32(99), 2);
        assert_eq!(column_width_for_u32(100), 3);
    }

    #[test]
    fn test_process_forest_fmt() {
        let mut roots = BTreeSet::new();
        roots.insert(1u32);

        let mut nodes = BTreeMap::new();
        let n1 = ProcessForestNode {
            process: Process {
                pid: 1,
                ppid: 0,
                cmdline: String::from("init"),
            },
            child_pids: vec![2, 5],
        };
        nodes.insert(n1.process.pid, n1);

        let n2 = ProcessForestNode {
            process: Process {
                pid: 2,
                ppid: 1,
                cmdline: String::from("foo"),
            },
            child_pids: vec![3, 4],
        };
        nodes.insert(n2.process.pid, n2);

        let n3 = ProcessForestNode {
            process: Process {
                pid: 3,
                ppid: 2,
                cmdline: String::from("bar"),
            },
            child_pids: vec![6, 7],
        };
        nodes.insert(n3.process.pid, n3);

        let n4 = ProcessForestNode {
            process: Process {
                pid: 4,
                ppid: 2,
                cmdline: String::from("baz"),
            },
            child_pids: vec![10],
        };
        nodes.insert(n4.process.pid, n4);

        let n5 = ProcessForestNode {
            process: Process {
                pid: 5,
                ppid: 1,
                cmdline: String::from("hoge"),
            },
            child_pids: vec![8],
        };
        nodes.insert(n5.process.pid, n5);

        let n6 = ProcessForestNode {
            process: Process {
                pid: 6,
                ppid: 3,
                cmdline: String::from("huga"),
            },
            child_pids: vec![],
        };
        nodes.insert(n6.process.pid, n6);

        let n7 = ProcessForestNode {
            process: Process {
                pid: 7,
                ppid: 3,
                cmdline: String::from("yay"),
            },
            child_pids: vec![],
        };
        nodes.insert(n7.process.pid, n7);

        let n8 = ProcessForestNode {
            process: Process {
                pid: 8,
                ppid: 5,
                cmdline: String::from("ls"),
            },
            child_pids: vec![9],
        };
        nodes.insert(n8.process.pid, n8);

        let n9 = ProcessForestNode {
            process: Process {
                pid: 9,
                ppid: 8,
                cmdline: String::from("cat"),
            },
            child_pids: vec![],
        };
        nodes.insert(n9.process.pid, n9);

        let n10 = ProcessForestNode {
            process: Process {
                pid: 10,
                ppid: 4,
                cmdline: String::from("top"),
            },
            child_pids: vec![],
        };
        nodes.insert(n10.process.pid, n10);

        let forest = ProcessForest { roots, nodes };
        let mut records = Vec::new();
        for pid in forest.roots.iter() {
            print_forest_helper(&forest, *pid, vec![], &mut records);
        }
        pad_columns(&mut records);
        for record in records {
            println!("{} {}", record.pid, record.cmdline);
        }
    }
}
