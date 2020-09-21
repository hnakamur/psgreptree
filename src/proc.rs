use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Local, TimeZone};
use futures_lite::stream::{self, StreamExt};
use futures_lite::*;
use humanize_number::{humanize_number, Flags, Scale};
use nix::sys::sysinfo;
use nix::unistd::{sysconf, SysconfVar, Uid};
use regex::Regex;
use smol::fs::{self, DirEntry};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::process;
use std::str;
use std::sync::Mutex;

use crate::user;

pub mod cmdline;
pub mod stat;
pub mod status;

#[derive(Debug, Clone)]
struct Process {
    pid: u32,
    state: String,
    ppid: u32,
    pgrp: u32,
    session: u32,
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

impl Process {
    fn format_uname_or_uid(&self, uid: Uid) -> String {
        lazy_static! {
            static ref UNAME_CACHE: Mutex<user::UserNameCache> =
                Mutex::new(user::UserNameCache::new());
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

        format!("{}:{:02}", u / 60, u % 60)
    }
}

#[derive(Debug, Clone)]
pub struct ProcessForest {
    roots: BTreeSet<u32>,
    nodes: BTreeMap<u32, ProcessForestNode>,
    herz: i64,
    btime: u64,
    uptime: std::time::Duration,
    now: DateTime<Local>,
    ram_total: u64,
}

#[derive(Debug, Clone)]
struct ProcessForestNode {
    process: Process,
    child_pids: Vec<u32>,
}

const HEADER_LABELS: [&str; 10] = [
    "USER", "PID", "%CPU", "%MEM", "VSZ", "RSS", "STAT", "START", "TIME", "COMMAND",
];

impl fmt::Display for ProcessForest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut records = Vec::new();
        for pid in self.roots.iter() {
            self.print_forest_helper(*pid, vec![], &mut records);
        }
        let widths = column_widths(&HEADER_LABELS[0..9], &records);
        writeln!(
            f,
            "{:user_w$} {:>pid_w$} {:cpu_w$} {:mem_w$} {:>vsz_w$} {:>rss_w$} {:stat_w$} {:start_w$} {:>time_w$} {}",
            HEADER_LABELS[0],
            HEADER_LABELS[1],
            HEADER_LABELS[2],
            HEADER_LABELS[3],
            HEADER_LABELS[4],
            HEADER_LABELS[5],
            HEADER_LABELS[6],
            HEADER_LABELS[7],
            HEADER_LABELS[8],
            HEADER_LABELS[9],
            user_w=widths[0],
            pid_w=widths[1],
            cpu_w=widths[2],
            mem_w=widths[3],
            vsz_w=widths[4],
            rss_w=widths[5],
            stat_w=widths[6],
            start_w=widths[7],
            time_w=widths[8],
        )?;
        for record in records {
            writeln!(
                f,
                "{:user_w$} {:>pid_w$} {:cpu_w$} {:mem_w$} {:>vsz_w$} {:>rss_w$} {:stat_w$} {:start_w$} {:>time_w$} {}",
                record.uname_or_uid,
                record.pid,
                record.cpu_percent,
                record.mem_percent,
                record.vsz,
                record.rss,
                record.stat,
                record.start_time,
                record.time,
                record.cmdline,
                user_w=widths[0],
                pid_w=widths[1],
                cpu_w=widths[2],
                mem_w=widths[3],
                vsz_w=widths[4],
                rss_w=widths[5],
                stat_w=widths[6],
                start_w=widths[7],
                time_w=widths[8],
            )?;
        }
        Ok(())
    }
}

fn column_widths(header_labels: &[&str], records: &[OutputLineRecord]) -> Vec<usize> {
    let mut widths: Vec<usize> = header_labels.into_iter().map(|label| label.len()).collect();
    for record in records {
        widths[0] = widths[0].max(record.uname_or_uid.len());
        widths[1] = widths[1].max(record.pid.len());
        widths[2] = widths[2].max(record.cpu_percent.len());
        widths[3] = widths[3].max(record.mem_percent.len());
        widths[4] = widths[4].max(record.vsz.len());
        widths[5] = widths[5].max(record.rss.len());
        widths[6] = widths[6].max(record.stat.len());
        widths[7] = widths[7].max(record.start_time.len());
        widths[8] = widths[8].max(record.time.len());
    }
    widths
}

struct OutputLineRecord {
    uname_or_uid: String,
    pid: String,
    cpu_percent: String,
    mem_percent: String,
    vsz: String,
    rss: String,
    stat: String,
    start_time: String,
    time: String,
    cmdline: String,
}

impl ProcessForest {
    pub async fn new(re: &Regex) -> Result<Self> {
        let pids = all_pids().await?;
        let procs = all_procs(pids).await?;
        let matched_pids = match_cmdline(&procs, re);
        let wanted_procs = get_matched_and_descendants(&procs, &matched_pids).await?;
        let btime = stat::get_btime().await?;
        let now = Local::now();
        let herz = sysconf(SysconfVar::CLK_TCK)
            .context("Failed to get sysconf CLK_TCK")?
            .context("No value for CLK_TCK")?;
        let sysinfo = sysinfo::sysinfo().context("Failed to get sysinfo")?;
        let uptime = sysinfo.uptime();
        let ram_total = sysinfo.ram_total();
        Ok(build_process_forest(
            wanted_procs,
            btime,
            now,
            herz,
            uptime,
            ram_total,
        ))
    }

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
            vsz: format_bytes_human(i64::try_from(node.process.vm_size).unwrap() * 1024),
            rss: format_bytes_human(i64::try_from(node.process.vm_rss).unwrap() * 1024),
            stat: node.process.format_stat(),
            start_time: node
                .process
                .format_start_time(self.herz, self.btime, self.now),
            time: node.process.format_time(self.herz),
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

fn format_bytes_human(bytes: i64) -> String {
    let mut buf = String::new();
    humanize_number(
        &mut buf,
        6,
        bytes,
        "",
        Scale::AutoScale,
        Flags::DECIMAL | Flags::NOSPACE | Flags::IEC_PREFIXES,
    )
    .unwrap();
    buf
}

async fn all_pids() -> Result<Vec<u32>> {
    let mut pids = Vec::new();
    let mut entries = fs::read_dir("/proc")
        .await
        .context("Failed to read /proc")?;
    while let Some(res) = entries.next().await {
        let entry = res.context("Get directory entry in /proc")?;
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
        match future::zip(stat::load_stat(pid), cmdline::read_cmdline(pid)).await {
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

fn match_cmdline(procs: &BTreeMap<u32, Process>, re: &Regex) -> BTreeSet<u32> {
    let mut pids = BTreeSet::new();
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
            let status = status::load_status(*pid).await?;
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
    herz: i64,
    uptime: std::time::Duration,
    ram_total: u64,
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
    ProcessForest {
        roots,
        nodes,
        herz,
        btime,
        uptime,
        now,
        ram_total,
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

#[cfg(test)]
mod test {
    use super::*;

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
