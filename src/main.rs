#[macro_use]
extern crate lazy_static;

use chrono::{DateTime, Duration, Local, TimeZone};
use clap::{App, Arg};
use futures_lite::stream::{self, StreamExt};
use futures_lite::*;
use nix::sys::sysinfo;
use nix::unistd::{sysconf, SysconfVar, Uid};
use regex::Regex;
use smol::fs::{read_dir, self, DirEntry, File};
use smol::io::AsyncBufReadExt;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::io::Result;
use std::process;
use std::str;
use std::sync::Mutex;

mod regex_util;
mod proc;
mod tty;
mod user;

#[derive(Debug, Clone)]
struct Process {
    pid: u32,
    state: String,
    ppid: u32,
    pgrp: u32,
    session: u32,
    tty_nr: i32,
    tpgid: i32,
    utime: u64,
    stime: u64,
    nice: i64,
    num_threads: i32,
    start_time: u64,

    cmdline: String,

    euid: Uid,
    vm_size: u64,
    vm_lock: u64,
    vm_rss: u64,
}

const UNAME_OR_UID_COL_WIDTH: usize = 8;
const CPU_PERCENT_COLUMN_WIDTH: usize = 4;
const MEM_PERCENT_COLUMN_WIDTH: usize = 4;
const VSZ_COLUMN_WIDTH: usize = 6;
const RSS_COLUMN_WIDTH: usize = 5;
const TTY_COLUMN_WIDTH: usize = 8;
const STAT_COLUMN_WIDTH: usize = 4;
const START_COLUMN_WIDTH: usize = 5;
const TIME_COLUMN_WIDTH: usize = 6;

impl Process {
    fn format_uname_or_uid(&self, uid: Uid) -> String {
        lazy_static! {
            static ref UNAME_CACHE: Mutex<user::UserNameCache> = Mutex::new(user::UserNameCache::new());
        }
        match UNAME_CACHE.lock().unwrap().get(uid) {
            Ok(Some(uname)) => {
                if uname.is_ascii() {
                    if uname.len() <= UNAME_OR_UID_COL_WIDTH {
                        format!("{:prec$}", uname, prec = UNAME_OR_UID_COL_WIDTH)
                    } else {
                        format!("{}+", uname.get(..UNAME_OR_UID_COL_WIDTH - 1).unwrap())
                    }
                } else {
                    format!("{:prec$}", uid, prec = UNAME_OR_UID_COL_WIDTH)
                }
            }
            _ => format!("{:prec$}", uid, prec = UNAME_OR_UID_COL_WIDTH),
        }
    }

    fn format_cpu_percent(&self, herz: i64, uptime: std::time::Duration) -> String {
        let total_time = (self.utime + self.stime) / (herz as u64);
        let etime = if uptime.as_secs() >= self.start_time / (herz as u64) {
            uptime.as_secs() - self.start_time / (herz as u64)
        } else {
            0
        };

        let cpu_percent = if etime > 0 {
            total_time * 1000 / etime
        } else {
            0
        };

        if cpu_percent > 999 {
            format!("{:>4}", cpu_percent / 10)
        } else {
            format!("{:>2}.{}", cpu_percent / 10, cpu_percent % 10)
        }
    }

    fn format_mem_percent(&self, ram_total: u64) -> String {
        let mem_percent = (self.vm_rss * 1000 / (ram_total / 1024)).min(999);
        format!("{:>2}.{}", mem_percent / 10, mem_percent % 10)
    }

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

    fn format_start_time(&self, herz: i64, btime: u64, now: DateTime<Local>) -> String {
        let start_time = Local.timestamp(
            i64::try_from(btime).unwrap() + i64::try_from(self.start_time).unwrap() / herz,
            0,
        );
        let dur = now.signed_duration_since(start_time);
        if dur > Duration::hours(24) {
            start_time.format("%b%d").to_string()
        } else {
            start_time.format("%H:%M").to_string()
        }
    }

    fn format_time(&self, herz: i64) -> String {
        let t = self.utime + self.stime;
        let u = (t as i64) / herz;

        format!("{:3}:{:02}", u / 60, u % 60)
    }
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
    btime: u64,
    uptime: std::time::Duration,
    now: DateTime<Local>,
    ram_total: u64,
}

impl ProcessForest {
    fn print_forest_helper(
        &self,
        pid: u32,
        last_child: Vec<bool>,
        records: &mut Vec<OutputLineRecord>,
    ) {
        let node = self.nodes.get(&pid).unwrap();
        records.push(OutputLineRecord {
            uname_or_uid: node.process.format_uname_or_uid(node.process.euid),
            pid: format!("{}", pid),
            cpu_percent: node.process.format_cpu_percent(self.herz, self.uptime),
            mem_percent: node.process.format_mem_percent(self.ram_total),
            vsz: format!("{}", node.process.vm_size),
            rss: format!("{}", node.process.vm_rss),
            tty: smol::block_on(async {
                tty::format_tty(node.process.tty_nr, node.process.pid)
                    .await
                    .unwrap()
            }),
            stat: format!(
                "{:stat_w$}",
                node.process.format_stat(),
                stat_w = STAT_COLUMN_WIDTH
            ),
            start_time: format!(
                "{:start_w$}",
                node.process
                    .format_start_time(self.herz, self.btime, self.now,),
                start_w = START_COLUMN_WIDTH
            ),
            time: format!(
                "{:>time_w$}",
                node.process.format_time(self.herz),
                time_w = TIME_COLUMN_WIDTH
            ),
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
            self.print_forest_helper(child_pid, last_child2, records);
            i += 1;
        }
    }
}

const COMMAND_LABEL: &str = "COMMAND";

impl fmt::Display for ProcessForest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut records = Vec::new();
        for pid in self.roots.iter() {
            self.print_forest_helper(*pid, vec![], &mut records);
        }
        let pid_w = smol::block_on(async { get_pid_digits().await });
        writeln!(
            f,
            "{:user_w$} {:>pid_w$} {:cpu_w$} {:mem_w$} {:>vsz_w$} {:>rss_w$} {:tty_w$} {:stat_w$} {:start_w$} {:>time_w$} {}",
            "USER", "PID", "%CPU", "%MEM", "VSZ", "RSS", "TTY", "STAT", "START", "TIME", COMMAND_LABEL,
            user_w=UNAME_OR_UID_COL_WIDTH,
            pid_w=pid_w,
            cpu_w=CPU_PERCENT_COLUMN_WIDTH,
            mem_w=MEM_PERCENT_COLUMN_WIDTH,
            vsz_w=VSZ_COLUMN_WIDTH,
            rss_w=RSS_COLUMN_WIDTH,
            tty_w=TTY_COLUMN_WIDTH,
            stat_w=STAT_COLUMN_WIDTH,
            start_w=START_COLUMN_WIDTH,
            time_w=TIME_COLUMN_WIDTH,
        )?;
        for record in records {
            let vsz_over = if record.vsz.len() > VSZ_COLUMN_WIDTH {
                record.vsz.len() - VSZ_COLUMN_WIDTH
            } else {
                0
            };
            let rss_w = if vsz_over == 0 {
                RSS_COLUMN_WIDTH
            } else if vsz_over < RSS_COLUMN_WIDTH {
                RSS_COLUMN_WIDTH - vsz_over
            } else {
                1
            };
            let rss_over = if record.rss.len() > rss_w {
                record.rss.len() - rss_w
            } else {
                0
            };
            let tty_w = if rss_over == 0 {
                TTY_COLUMN_WIDTH
            } else if rss_over < TTY_COLUMN_WIDTH {
                TTY_COLUMN_WIDTH - rss_over
            } else {
                1
            };
            writeln!(
                f,
                "{} {:>pid_w$} {} {} {:>vsz_w$} {:>rss_w$} {:tty_w$} {} {} {} {}",
                record.uname_or_uid,
                record.pid,
                record.cpu_percent,
                record.mem_percent,
                record.vsz,
                record.rss,
                record.tty,
                record.stat,
                record.start_time,
                record.time,
                record.cmdline,
                pid_w = pid_w,
                vsz_w = VSZ_COLUMN_WIDTH,
                rss_w = rss_w,
                tty_w = tty_w,
            )?;
        }
        Ok(())
    }
}

async fn get_pid_digits() -> usize {
    const DEFAULT_WIDTH: usize = 5;
    fs::read("/proc/sys/kernel/pid_max")
        .await
        .map_or(DEFAULT_WIDTH, |data| {
            str::from_utf8(&data).map_or(DEFAULT_WIDTH, |text| {
                text.trim()
                    .parse::<u32>()
                    .map_or(DEFAULT_WIDTH, |max_pid| column_width_for_u32(max_pid - 1))
            })
        })
}

struct OutputLineRecord {
    uname_or_uid: String,
    pid: String,
    cpu_percent: String,
    mem_percent: String,
    vsz: String,
    rss: String,
    stat: String,
    tty: String,
    start_time: String,
    time: String,
    cmdline: String,
}

fn main() {
    let matches = App::new("psgreptree")
        .version("0.1.0")
        .author("Hiroaki Nakamura <hnakamur@gmail.com>")
        .about("show process tree filtered by pattern match for command lines")
        .arg(
            Arg::with_name("PATTERN")
                .value_name("pattern")
                .help("Sets a regular expression to match process command lines")
                .default_value(".*")
                .index(1),
        )
        .get_matches();
    let pattern = matches.value_of("PATTERN");

    std::env::set_var("SMOL_THREADS", format!("{}", num_cpus::get()));

    smol::block_on(async {
        let pids = all_pids().await.unwrap();
        let procs = all_procs(pids).await.unwrap();
        let matched_pids = match_cmdline(&procs, pattern.unwrap());
        let wanted_procs = get_matched_and_descendants(&procs, &matched_pids)
            .await
            .unwrap();
        let btime = get_btime().await.unwrap();
        let now = Local::now();
        let proc_forest = build_process_forest(wanted_procs, btime, now);
        print!("{}", proc_forest);
    });
}

async fn all_pids() -> Result<Vec<u32>> {
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

async fn all_procs(all_pids: Vec<u32>) -> Result<BTreeMap<u32, Process>> {
    let mut pids = BTreeMap::new();
    let mut s = stream::iter(all_pids);
    while let Some(pid) = s.next().await {
        match future::zip(proc::stat::load_stat(pid), read_cmdline(pid)).await {
            (Ok(stat), Ok(mut cmdline)) => {
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
                    tty_nr: stat.tty_nr,
                    tpgid: stat.tpgid,
                    utime: stat.utime,
                    stime: stat.stime,
                    nice: stat.nice,
                    num_threads: stat.num_threads,
                    start_time: stat.start_time,
                    cmdline,
                    euid: Uid::from_raw(0),
                    vm_size: 0,
                    vm_lock: 0,
                    vm_rss: 0,
                };
                pids.insert(pid, proc);
            }
            (Err(e), _) => return Err(e),
            (_, Err(e)) => return Err(e),
        };
    }
    Ok(pids)
}

async fn read_cmdline(pid: u32) -> Result<String> {
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

async fn get_matched_and_descendants(
    procs: &BTreeMap<u32, Process>,
    matched_pids: &BTreeSet<u32>,
) -> Result<BTreeMap<u32, Process>> {
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
            let mut proc = procs.get(pid).unwrap().clone();
            let status = proc::status::load_status(*pid).await.expect("read_status");
            proc.euid = status.euid;
            proc.vm_size = status.vm_size;
            proc.vm_lock = status.vm_lock;
            proc.vm_rss = status.vm_rss;
            wanted_procs.insert(*pid, proc);
        }
    }
    Ok(wanted_procs)
}

fn build_process_forest(
    procs: BTreeMap<u32, Process>,
    btime: u64,
    now: DateTime<Local>,
) -> ProcessForest {
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
    let sysinfo = sysinfo::sysinfo().expect("sysinfo");
    ProcessForest {
        roots,
        nodes,
        herz,
        btime,
        uptime: sysinfo.uptime(),
        now,
        ram_total: sysinfo.ram_total(),
    }
}

async fn get_btime() -> Result<u64> {
    const PATH: &str = "/proc/stat";
    let file = File::open(PATH).await?;
    let reader = smol::io::BufReader::new(file);
    lazy_static! {
        static ref BTIME_RE: Regex = Regex::new(r"^btime[\t ]+(\d+)").unwrap();
    }

    let mut lines = reader.lines();
    let mut btime = 0u64;
    while let Some(line) = lines.next().await {
        let line = line.unwrap();
        if let Some(caps) = BTIME_RE.captures(&line) {
            btime = caps.get(1).unwrap().as_str().parse::<u64>().unwrap();
        }
    }
    Ok(btime)
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
                tty_nr: 0,
                tpgid: 0,
                utime: 0,
                stime: 0,
                nice: 0,
                num_threads: 0,
                start_time: 0,
                euid: Uid::from_raw(0),
                vm_size: 0,
                vm_lock: 0,
                vm_rss: 0,
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
                tty_nr: 0,
                tpgid: 0,
                utime: 0,
                stime: 0,
                nice: 0,
                num_threads: 0,
                start_time: 0,
                euid: Uid::from_raw(0),
                vm_size: 0,
                vm_lock: 0,
                vm_rss: 0,
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
                tty_nr: 0,
                tpgid: 0,
                utime: 0,
                stime: 0,
                nice: 0,
                num_threads: 0,
                start_time: 0,
                euid: Uid::from_raw(0),
                vm_size: 0,
                vm_lock: 0,
                vm_rss: 0,
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
                tty_nr: 0,
                tpgid: 0,
                utime: 0,
                stime: 0,
                nice: 0,
                num_threads: 0,
                start_time: 0,
                euid: Uid::from_raw(0),
                vm_size: 0,
                vm_lock: 0,
                vm_rss: 0,
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
                tty_nr: 0,
                tpgid: 0,
                utime: 0,
                stime: 0,
                nice: 0,
                num_threads: 0,
                start_time: 0,
                euid: Uid::from_raw(0),
                vm_size: 0,
                vm_lock: 0,
                vm_rss: 0,
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
                tty_nr: 0,
                tpgid: 0,
                utime: 0,
                stime: 0,
                nice: 0,
                num_threads: 0,
                start_time: 0,
                euid: Uid::from_raw(0),
                vm_size: 0,
                vm_lock: 0,
                vm_rss: 0,
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
                tty_nr: 0,
                tpgid: 0,
                utime: 0,
                stime: 0,
                nice: 0,
                num_threads: 0,
                start_time: 0,
                euid: Uid::from_raw(0),
                vm_size: 0,
                vm_lock: 0,
                vm_rss: 0,
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
                tty_nr: 0,
                tpgid: 0,
                utime: 0,
                stime: 0,
                nice: 0,
                num_threads: 0,
                start_time: 0,
                euid: Uid::from_raw(0),
                vm_size: 0,
                vm_lock: 0,
                vm_rss: 0,
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
                tty_nr: 0,
                tpgid: 0,
                utime: 0,
                stime: 0,
                nice: 0,
                num_threads: 0,
                start_time: 0,
                euid: Uid::from_raw(0),
                vm_size: 0,
                vm_lock: 0,
                vm_rss: 0,
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
                tty_nr: 0,
                tpgid: 0,
                utime: 0,
                stime: 0,
                nice: 0,
                num_threads: 0,
                start_time: 0,
                euid: Uid::from_raw(0),
                vm_size: 0,
                vm_lock: 0,
                vm_rss: 0,
            },
            child_pids: vec![],
        };
        nodes.insert(n10.process.pid, n10);

        const HERZ: i64 = 100;
        const BTIME: u64 = 0;
        let forest = ProcessForest {
            roots,
            nodes,
            herz: HERZ,
            btime: BTIME,
            uptime: std::time::Duration::from_secs(0),
            now: Local::now(),
            ram_total: 1024,
        };
        let mut records = Vec::new();
        for pid in forest.roots.iter() {
            forest.print_forest_helper(*pid, vec![], &mut records);
        }
        for record in records {
            println!("{} {}", record.pid, record.cmdline);
        }
    }
}
