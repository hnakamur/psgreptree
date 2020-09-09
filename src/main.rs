#![feature(map_first_last)]
use std::collections::BTreeMap;

#[macro_use]
extern crate lazy_static;

use async_fs::{read_dir, DirEntry, File};
use clap::{App, Arg};
use futures_lite::stream::{self, StreamExt};
use futures_lite::*;
use nix::unistd::{sysconf, SysconfVar};
use regex::Regex;
use std::cmp;
use std::collections::{BTreeSet, HashMap};
use std::convert::TryInto;
use std::fmt;
use std::io;
use std::process;
use std::str;

#[derive(Debug, Clone)]
struct Process {
    pid: u32,
    state: String,
    ppid: u32,
    pgrp: u32,
    session: u32,
    tpgid: i32,
    utime: u32,
    stime: u32,
    nice: i32,
    num_threads: i32,
    vm_lock: u32,
    cmdline: String,
}

impl Process {
    fn format_stat(&self) -> String {
        let mut stat = self.state.clone();
        match self.nice.signum() {
            1 => stat.push('<'),
            -1 => stat.push('N'),
            _ => {}
        }
        if self.vm_lock != 0 {
            stat.push('L');
        }
        if self.session == self.pid {
            stat.push('s'); // session leader
        }
        if self.num_threads > 1 {
            stat.push('l'); // multi-threaded
        }
        if self.tpgid == self.pgrp.try_into().unwrap() {
            stat.push('+'); // in foreground process group
        }
        stat
    }

    fn format_time(&self, herz: i64) -> String {
        let t = self.utime + self.stime;
        let u = (t as i64) / herz;

        format!("{:3}:{:02}", u / 60, u % 60)
    }
}

#[derive(Debug, Clone)]
struct ProcStat {
    comm: String,
    state: String,
    ppid: u32,
    pgrp: u32,
    session: u32,
    tpgid: i32,
    utime: u32,
    stime: u32,
    nice: i32,
    num_threads: i32,
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
    herz: i64,
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
            writeln!(
                f,
                "{} {} {} {}",
                record.pid, record.stat, record.time, record.cmdline
            )?;
        }
        Ok(())
    }
}

struct OutputLineRecord {
    pid: String,
    stat: String,
    time: String,
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
        match future::zip(get_stat(pid), get_cmdline_and_vm_lock(pid)).await {
            (Ok(stat), Ok((mut cmdline, vm_lock))) => {
                if stat.state == "Z" {
                    cmdline = format!("[{}] <defunct>", &stat.comm);
                }
                if cmdline == "" {
                    cmdline = format!("[{}]", stat.comm);
                }
                let proc = Process {
                    pid,
                    ppid: stat.ppid,
                    state: stat.state,
                    pgrp: stat.pgrp,
                    session: stat.session,
                    tpgid: stat.tpgid,
                    utime: stat.utime,
                    stime: stat.stime,
                    nice: stat.nice,
                    num_threads: stat.num_threads,
                    cmdline,
                    vm_lock,
                };
                pids.insert(pid, proc);
            }
            (Err(e), _) => return Err(e),
            (_, Err(e)) => return Err(e),
        };
    }
    Ok(pids)
}

async fn get_stat(pid: u32) -> io::Result<ProcStat> {
    lazy_static! {
        // https://elixir.bootlin.com/linux/latest/C/ident/do_task_stat
        static ref STAT_RE: Regex = Regex::new(r"^(?P<pid>\d+) \((?P<comm>.+?)\) (?P<state>.) (?P<ppid>\d+) (?P<pgrp>\d+) (?P<session>\d+) (?P<tty_nr>\d+) (?P<tpgid>-?\d+) (?P<flags>-?\d+) (?P<minflt>\d+) (?P<cminflt>\d+) (?P<majflt>\d+) (?P<cmajflt>\d+) (?P<utime>\d+) (?P<stime>\d+) (?P<cutime>-?\d+) (?P<cstime>-?\d+) (?P<priority>-?\d+) (?P<nice>-?\d+) (?P<num_threads>-?\d+) (?P<itrealvalue>-?\d+) (?P<starttime>\d+) (?P<vsize>\d+) (?P<rss>\d+)").unwrap();
    }

    let path = format!("/proc/{}/stat", pid);
    let data = async_fs::read(path).await?;
    let text = str::from_utf8(&data).unwrap();
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
    let tpgid = cap.name("tpgid").unwrap().as_str().parse::<i32>().unwrap();
    let utime = cap.name("utime").unwrap().as_str().parse::<u32>().unwrap();
    let stime = cap.name("stime").unwrap().as_str().parse::<u32>().unwrap();
    let nice = cap.name("nice").unwrap().as_str().parse::<i32>().unwrap();
    let num_threads = cap
        .name("num_threads")
        .unwrap()
        .as_str()
        .parse::<i32>()
        .unwrap();
    Ok(ProcStat {
        comm,
        state,
        ppid,
        pgrp,
        session,
        tpgid,
        utime,
        stime,
        nice,
        num_threads,
    })
}

async fn get_cmdline_and_vm_lock(pid: u32) -> io::Result<(String, u32)> {
    match future::zip(get_cmdline(pid), read_vm_lock_in_status(pid)).await {
        (Ok(cmdline), Ok(vm_lock)) => Ok((cmdline, vm_lock)),
        (Err(e), _) => Err(e),
        (_, Err(e)) => Err(e),
    }
}

async fn read_vm_lock_in_status(pid: u32) -> io::Result<u32> {
    let path = format!("/proc/{}/status", pid);
    let file = File::open(path).await?;
    let reader = smol::io::BufReader::new(file);
    lazy_static! {
        static ref VMLCK_RE: Regex = Regex::new(r"^VmLck:[\t ]*(\d+)").unwrap();
    }

    let mut lines = reader.lines();
    let mut vm_lock = 0u32;
    while let Some(line) = lines.next().await {
        let line = line.unwrap();
        if let Some(caps) = VMLCK_RE.captures(&line) {
            vm_lock = caps.get(1).unwrap().as_str().parse::<u32>().unwrap();
        }
    }
    Ok(vm_lock)
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
    let herz = sysconf(SysconfVar::CLK_TCK)
        .expect("sysconf CLK_TCK")
        .unwrap();
    ProcessForest { roots, nodes, herz }
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

fn print_forest_helper(
    f: &ProcessForest,
    pid: u32,
    last_child: Vec<bool>,
    records: &mut Vec<OutputLineRecord>,
) {
    let node = f.nodes.get(&pid).unwrap();
    records.push(OutputLineRecord {
        pid: format!("{}", pid),
        stat: format!("{:4}", node.process.format_stat()),
        time: format!("{:>6}", node.process.format_time(f.herz)),
        cmdline: format!(
            "{}{}",
            last_child_to_indent(&last_child),
            node.process.cmdline
        ),
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

fn get_max_pid_column_width(records: &[OutputLineRecord]) -> usize {
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
    use smol::io::{self, AsyncBufReadExt};
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
                state: String::from("S"),
                cmdline: String::from("init"),
                pgrp: 0,
                session: 0,
                tpgid: 0,
                utime: 0,
                stime: 0,
                nice: 0,
                num_threads: 0,
                vm_lock: 0,
            },
            child_pids: vec![2, 5],
        };
        nodes.insert(n1.process.pid, n1);

        let n2 = ProcessForestNode {
            process: Process {
                pid: 2,
                ppid: 1,
                state: String::from("S"),
                cmdline: String::from("foo"),
                pgrp: 0,
                session: 0,
                tpgid: 0,
                utime: 0,
                stime: 0,
                nice: 0,
                num_threads: 0,
                vm_lock: 0,
            },
            child_pids: vec![3, 4],
        };
        nodes.insert(n2.process.pid, n2);

        let n3 = ProcessForestNode {
            process: Process {
                pid: 3,
                ppid: 2,
                state: String::from("S"),
                cmdline: String::from("bar"),
                pgrp: 0,
                session: 0,
                tpgid: 0,
                utime: 0,
                stime: 0,
                nice: 0,
                num_threads: 0,
                vm_lock: 0,
            },
            child_pids: vec![6, 7],
        };
        nodes.insert(n3.process.pid, n3);

        let n4 = ProcessForestNode {
            process: Process {
                pid: 4,
                ppid: 2,
                state: String::from("S"),
                cmdline: String::from("baz"),
                pgrp: 0,
                session: 0,
                tpgid: 0,
                utime: 0,
                stime: 0,
                nice: 0,
                num_threads: 0,
                vm_lock: 0,
            },
            child_pids: vec![10],
        };
        nodes.insert(n4.process.pid, n4);

        let n5 = ProcessForestNode {
            process: Process {
                pid: 5,
                ppid: 1,
                state: String::from("S"),
                cmdline: String::from("hoge"),
                pgrp: 0,
                session: 0,
                tpgid: 0,
                utime: 0,
                stime: 0,
                nice: 0,
                num_threads: 0,
                vm_lock: 0,
            },
            child_pids: vec![8],
        };
        nodes.insert(n5.process.pid, n5);

        let n6 = ProcessForestNode {
            process: Process {
                pid: 6,
                ppid: 3,
                state: String::from("S"),
                cmdline: String::from("huga"),
                pgrp: 0,
                session: 0,
                tpgid: 0,
                utime: 0,
                stime: 0,
                nice: 0,
                num_threads: 0,
                vm_lock: 0,
            },
            child_pids: vec![],
        };
        nodes.insert(n6.process.pid, n6);

        let n7 = ProcessForestNode {
            process: Process {
                pid: 7,
                ppid: 3,
                state: String::from("S"),
                cmdline: String::from("yay"),
                pgrp: 0,
                session: 0,
                tpgid: 0,
                utime: 0,
                stime: 0,
                nice: 0,
                num_threads: 0,
                vm_lock: 0,
            },
            child_pids: vec![],
        };
        nodes.insert(n7.process.pid, n7);

        let n8 = ProcessForestNode {
            process: Process {
                pid: 8,
                ppid: 5,
                state: String::from("S"),
                cmdline: String::from("ls"),
                pgrp: 0,
                session: 0,
                tpgid: 0,
                utime: 0,
                stime: 0,
                nice: 0,
                num_threads: 0,
                vm_lock: 0,
            },
            child_pids: vec![9],
        };
        nodes.insert(n8.process.pid, n8);

        let n9 = ProcessForestNode {
            process: Process {
                pid: 9,
                ppid: 8,
                state: String::from("S"),
                cmdline: String::from("cat"),
                pgrp: 0,
                session: 0,
                tpgid: 0,
                utime: 0,
                stime: 0,
                nice: 0,
                num_threads: 0,
                vm_lock: 0,
            },
            child_pids: vec![],
        };
        nodes.insert(n9.process.pid, n9);

        let n10 = ProcessForestNode {
            process: Process {
                pid: 10,
                ppid: 4,
                state: String::from("S"),
                cmdline: String::from("top"),
                pgrp: 0,
                session: 0,
                tpgid: 0,
                utime: 0,
                stime: 0,
                nice: 0,
                num_threads: 0,
                vm_lock: 0,
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

    #[test]
    fn test_read_proc_status() {
        // https://elixir.bootlin.com/linux/latest/C/ident/proc_pid_status
        // https://elixir.bootlin.com/linux/latest/C/ident/proc_task_name
        let input = b"Name:	mozc_server\n\
            Umask:	0002\n\
            State:	S (sleeping)\n\
            Tgid:	1899\n\
            Ngid:	0\n\
            Pid:	1899\n\
            PPid:	1845\n\
            TracerPid:	0\n\
            Uid:	1000	1000	1000	1000\n\
            Gid:	1000	1000	1000	1000\n\
            FDSize:	64\n\
            Groups:	4 24 27 30 46 120 131 132 998 1000 \n\
            NStgid:	1899\n\
            NSpid:	1899\n\
            NSpgid:	1844\n\
            NSsid:	1844\n\
            VmPeak:	   74400 kB\n\
            VmSize:	   74400 kB\n\
            VmLck:	   12916 kB\n\
            VmPin:	       0 kB\n\
            VmHWM:	   29056 kB\n\
            VmRSS:	   29056 kB\n\
            RssAnon:	    5288 kB\n\
            RssFile:	   23768 kB\n\
            RssShmem:	       0 kB\n\
            VmData:	   46876 kB\n\
            VmStk:	     132 kB\n\
            VmExe:	    1340 kB\n\
            VmLib:	    5048 kB\n\
            VmPTE:	     116 kB\n\
            VmSwap:	       0 kB\n\
            HugetlbPages:	       0 kB\n\
            CoreDumping:	0\n\
            THP_enabled:	1\n\
            Threads:	5\n\
            SigQ:	1/62534\n\
            SigPnd:	0000000000000000\n\
            ShdPnd:	0000000000000000\n\
            SigBlk:	0000000000000000\n\
            SigIgn:	0000000008003800\n\
            SigCgt:	0000000180000000\n\
            CapInh:	0000000000000000\n\
            CapPrm:	0000000000000000\n\
            CapEff:	0000000000000000\n\
            CapBnd:	0000003fffffffff\n\
            CapAmb:	0000000000000000\n\
            NoNewPrivs:	0\n\
            Seccomp:	0\n\
            Speculation_Store_Bypass:	thread vulnerable\n\
            Cpus_allowed:	ffffffff\n\
            Cpus_allowed_list:	0-31\n\
            Mems_allowed:	00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000001\n\
            Mems_allowed_list:	0\n\
            voluntary_ctxt_switches:	70\n\
            nonvoluntary_ctxt_switches:	2\n";
        let reader = io::BufReader::new(&input[..]);
        lazy_static! {
            static ref VMLCK_RE: Regex = Regex::new(r"^VmLck:[\t ]*(\d+)").unwrap();
        }

        smol::block_on(async {
            let mut lines = reader.lines();
            while let Some(line) = lines.next().await {
                let line = line.unwrap();
                if let Some(caps) = VMLCK_RE.captures(&line) {
                    let value = caps.get(1).unwrap().as_str();
                    println!("VmLck={}", value);
                    break;
                }
            }
        });
    }

    #[test]
    fn test_stat_regex_captures() {
        // let re = Regex::new(r"^(?P<pid>\d+) \((?P<comm>.+?)\) (?P<state>.) (?P<ppid>\d+) (?P<pgrp>\d+) (?P<session>\d+) (?P<tty_nr>\d+) (?P<tpgid>-?\d+) (?P<flags>-?\d+) (?P<minflt>\d+) (?P<cminflt>\d+) (?P<majflt>\d+) (?P<cmajflt>\d+) (?P<utime>\d+) (?P<stime>\d+) (?P<priority>-?\d+) (?P<nice>-?\d+) (?P<num_threads>\d+) (?P<itrealvalue>-?\d+) (?P<starttime>\d+) (?P<vsize>\d+) (?P<rss>\d+)").unwrap();

        let re = Regex::new(r"^(?P<pid>\d+) \((?P<comm>.+?)\) (?P<state>.) (?P<ppid>\d+) (?P<pgrp>\d+) (?P<session>\d+) (?P<tty_nr>\d+) (?P<tpgid>-?\d+) (?P<flags>-?\d+) (?P<minflt>\d+) (?P<cminflt>\d+) (?P<majflt>\d+) (?P<cmajflt>\d+) (?P<utime>\d+) (?P<stime>\d+) (?P<priority>-?\d+) (?P<nice>-?\d+) (?P<num_threads>-?\d+) (?P<itrealvalue>-?\d+) (?P<starttime>\d+) (?P<vsize>\d+) (?P<rss>\d+)").unwrap();
        // let caps = re.captures("3 (rcu_gp) I 2 0 0 0 -1 69238880 0 0 0 0 0 0 0 0 0 -20 1 0 15 0 0 18446744073709551615 0 0 0 0 0 0 0 2147483647 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0");
        let caps = re.captures("12 (migration/0) S 2 0 0 0 -1 69238848 0 0 0 0 1 0 0 0 -100 0 1 0 15 0 0 18446744073709551615 0 0 0 0 0 0 0 2147483647 0 0 0 0 17 0 99 1 0 0 0 0 0 0 0 0 0 0 0");
        println!("caps={:?}", caps);
    }
}
