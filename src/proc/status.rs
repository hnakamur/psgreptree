use crate::regex_util::CapturesAdapter;
use anyhow::{Context, Result};
use nix::unistd::Uid;
use regex::Regex;
use smol::fs::File;
use smol::io::BufReader;
use smol::prelude::{AsyncBufReadExt, AsyncReadExt, StreamExt};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Status {
    pub euid: Uid,
    pub vm_size: u64,
    pub vm_lock: u64,
    pub vm_rss: u64,
}

pub async fn load_status(pid: u32) -> Result<Status> {
    let path = format!("/proc/{}/status", pid);
    let file = File::open(&path)
        .await
        .with_context(|| format!("cannot open file {}", &path))?;
    read_status(BufReader::new(file))
        .await
        .with_context(|| format!("read error for {}", &path))
}

async fn read_status<R: AsyncReadExt + Unpin>(reader: BufReader<R>) -> Result<Status> {
    lazy_static! {
        static ref KEY_VAL_RE: Regex = Regex::new(r"^(.*?):[\t ]*(.+)").unwrap();
        static ref EUID_RE: Regex = Regex::new(r"^\d+\t(\d+)").unwrap();
        static ref KB_RE: Regex = Regex::new(r"^(\d+)").unwrap();
    }

    let mut euid: Uid = Uid::from_raw(0);
    let mut vm_size = 0u64;
    let mut vm_lock = 0u64;
    let mut vm_rss = 0u64;
    let mut lines = reader.lines();
    while let Some(line) = lines.next().await {
        if let Some(caps) = KEY_VAL_RE.captures(&line?) {
            let caps = CapturesAdapter::new(caps);
            let key = caps.str_by_index(1);
            let value = caps.str_by_index(2);
            match key {
                "Uid" => {
                    let caps = EUID_RE.captures(value).with_context(|| {
                        format!("regex match failed for Uid (value was {})", value)
                    })?;
                    let caps = CapturesAdapter::new(caps);
                    euid = Uid::from_raw(caps.int_by_index::<u32>(1)?);
                }
                "VmSize" => {
                    let caps = KB_RE.captures(value).with_context(|| {
                        format!("regex match failed for VmSize (value was {})", value)
                    })?;
                    let caps = CapturesAdapter::new(caps);
                    vm_size = caps.int_by_index::<u64>(1)?;
                }
                "VmLck" => {
                    let caps = KB_RE.captures(value).with_context(|| {
                        format!("regex match failed for VmLck (value was {})", value)
                    })?;
                    let caps = CapturesAdapter::new(caps);
                    vm_lock = caps.int_by_index::<u64>(1)?
                }
                "VmRSS" => {
                    let caps = KB_RE.captures(value).with_context(|| {
                        format!("regex match failed for VmRSS (value was {})", value)
                    })?;
                    let caps = CapturesAdapter::new(caps);
                    vm_rss = caps.int_by_index::<u64>(1)?;
                }
                _ => {}
            }
        }
    }
    Ok(Status {
        euid,
        vm_size,
        vm_lock,
        vm_rss,
    })
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_read_status() {
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
        let reader = BufReader::new(&input[..]);
        let wanted = Status {
            euid: Uid::from_raw(1000),
            vm_size: 74400,
            vm_lock: 12916,
            vm_rss: 29056,
        };
        let status = smol::block_on(async { read_status(reader).await.unwrap() });
        assert_eq!(status, wanted);
    }
}
