#[macro_use]
extern crate lazy_static;

use async_fs::{read_dir, DirEntry};
use clap::{App, Arg};
use futures_lite::stream::{self, StreamExt};
use regex::Regex;
use std::collections::HashMap;
use std::io;
use std::str;

#[derive(Debug)]
struct Process {
    pid: i32,
    ppid: i32,
    wanted: Option<bool>,
    cmdline: Option<String>,
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
        let mut procs = all_procs(pids).await.unwrap();

        fill_cmdline_for_matches(&mut procs, pattern.unwrap()).await.unwrap();
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
    lazy_static! {
        static ref PPID_RE: Regex = Regex::new(r"\) . (\d+)").unwrap();
    }

    let mut pids = HashMap::new();
    let mut s = stream::iter(all_pids);
    while let Some(pid) = s.next().await {
        let path = format!("/proc/{}/stat", pid);
        let data = async_fs::read(path).await?;
        let text = str::from_utf8(&data).unwrap();
        let caps = PPID_RE.captures(text).unwrap();
        let ppid = caps.get(1).unwrap().as_str().parse::<i32>().unwrap();
        let proc = Process{
            pid, ppid, wanted: None, cmdline: None,
        };
        pids.insert(pid, proc);
    }
    Ok(pids)
}

async fn fill_cmdline_for_matches(procs: &mut HashMap<i32, Process>, pattern: &str) -> io::Result<()> {
    let re = Regex::new(pattern).expect("valid regular expression");
    let mut s = stream::iter(procs);
    while let Some((pid, mut proc)) = s.next().await {
        let path = format!("/proc/{}/cmdline", pid);
        let data = async_fs::read(path).await?;
        let raw_cmdline = String::from_utf8(data).unwrap();
        let words: Vec<&str> = raw_cmdline.trim_end_matches('\0').split('\0').collect();
        let cmdline = if words == vec![""] { String::from("") } else { shellwords::join(&words) };
        println!("cmdline={:?}", cmdline);
        // let cmdline = cmdline.replace("\0", " ").trim_end().to_string();
        // if re.is_match(&cmdline) {
        //     proc.wanted = Some(true);
        //     proc.cmdline = Some(cmdline);
        // }
    }
    Ok(())
}

// fn mark_wanted(procs: &mut HashMap<i32, Process>) {
//     for proc in procs.values_mut() {
//         mark_wanted_one(&procs, proc);
//     }
// }

// fn mark_wanted_one(procs: &mut HashMap<i32, Process>, proc: &mut Process) {
//     if proc.ppid == 0 {
//         proc.wanted = Some(false);
//         return;
//     }

//     if let Some(parent_proc) = procs.get_mut(&proc.pid) {
//         if let Some(parent_wanted) = parent_proc.wanted {
//             proc.wanted = Some(parent_wanted);
//             return;
//         } else {
//             mark_wanted_one(procs, parent_proc);
//         }
//     }
//     proc.wanted = Some(false)
// }
