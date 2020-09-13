use regex::Regex;
use smol::fs::{self, File};
use smol::io::BufReader;
use smol::prelude::{AsyncBufReadExt, AsyncReadExt, StreamExt};
use std::convert::TryFrom;
use std::io::Result;
use std::os::linux::fs::MetadataExt;
use std::path::PathBuf;

#[derive(Debug, Eq, PartialEq, Clone)]
struct TtyDriver {
    name: String,
    major: i32,
    minor_first: i32,
    minor_last: i32,
    is_devfs: bool,
}

pub async fn format_tty(tty_nr: i32, pid: u32) -> Result<String> {
    lazy_static! {
        static ref DRIVERS: Vec<TtyDriver> =
            smol::block_on(async { load_tty_drivers().await.expect("load tty drivers") });
    }
    if tty_nr == 0 {
        Ok(String::from("?"))
    } else {
        let major = nix::sys::stat::major(tty_nr as u64);
        let minor = nix::sys::stat::minor(tty_nr as u64);
        let buf = if let Some(buf) = driver_name(&DRIVERS, major, minor).await {
            buf
        } else if let Some(buf) = link_name(major, minor, pid, "fd/2").await {
            buf
        } else if let Some(buf) = guess_name(major, minor).await {
            buf
        } else if let Some(buf) = link_name(major, minor, pid, "fd/255").await {
            buf
        } else {
            return Ok(String::from("?"));
        };
        let buf = buf.to_str().expect("pathbuf to str").to_string();
        const DEV_PREFIX: &str = "/dev/";
        if buf.starts_with(DEV_PREFIX) {
            Ok(String::from(&buf[DEV_PREFIX.len()..]))
        } else {
            Ok(buf)
        }
    }
}

async fn load_tty_drivers() -> Result<Vec<TtyDriver>> {
    let file = File::open("/proc/tty/drivers").await?;
    read_tty_drivers(BufReader::new(file)).await
}

async fn read_tty_drivers<R: AsyncReadExt + Unpin>(reader: BufReader<R>) -> Result<Vec<TtyDriver>> {
    // /proc/tty/drivers
    // https://elixir.bootlin.com/linux/latest/C/ident/proc_tty_init
    // https://elixir.bootlin.com/linux/latest/C/ident/tty_drivers_op
    // https://elixir.bootlin.com/linux/latest/C/ident/show_tty_driver
    // https://elixir.bootlin.com/linux/latest/C/ident/show_tty_range

    lazy_static! {
        static ref RECORD_RE: Regex =
            Regex::new(r"^[^ ]+ +/dev/([^ ]+) +(\d+) +(\d+)(-(\d+))?").unwrap();
    }

    let mut records = Vec::new();
    let mut lines = reader.lines();
    while let Some(line) = lines.next().await {
        if let Some(caps) = RECORD_RE.captures(&line?) {
            let mut name = caps.get(1).unwrap().as_str().to_string();
            let is_devfs = name.ends_with("%d");
            if is_devfs {
                name.truncate(name.len() - "%d".len());
            }
            let major = caps.get(2).unwrap().as_str().parse::<i32>().unwrap();
            let minor_first = caps.get(3).unwrap().as_str().parse::<i32>().unwrap();
            let minor_last = caps
                .get(5)
                .map_or(minor_first, |m| m.as_str().parse::<i32>().unwrap());
            let record = TtyDriver {
                name,
                major,
                minor_first,
                minor_last,
                is_devfs,
            };
            records.push(record);
        }
    }
    Ok(records)
}

async fn driver_name(drivers: &[TtyDriver], major: u64, minor: u64) -> Option<PathBuf> {
    if let Some(driver) = find_tty_driver(drivers, major, minor) {
        let buf = format!("/dev/{}{}", driver.name, minor); // like "/dev/ttyZZ255"
        match fs::metadata(&buf).await {
            Ok(m) => {
                if does_rdev_match(m, major, minor) {
                    Some(PathBuf::from(buf))
                } else {
                    None
                }
            }
            Err(_) => {
                let buf = format!("/dev/{}/{}", driver.name, minor); // like "/dev/pts/255"
                match fs::metadata(&buf).await {
                    Ok(m) => {
                        if does_rdev_match(m, major, minor) {
                            Some(PathBuf::from(buf))
                        } else {
                            None
                        }
                    }
                    Err(_) => {
                        let buf = format!("/dev/{}", driver.name); // like "/dev/ttyZZ255"
                        match fs::metadata(&buf).await {
                            Ok(m) => {
                                if does_rdev_match(m, major, minor) {
                                    Some(PathBuf::from(buf))
                                } else {
                                    None
                                }
                            }
                            Err(_) => None,
                        }
                    }
                }
            }
        }
    } else {
        None
    }
}

fn does_rdev_match(m: std::fs::Metadata, major: u64, minor: u64) -> bool {
    nix::sys::stat::major(m.st_rdev()) == major && nix::sys::stat::minor(m.st_rdev()) == minor
}

fn find_tty_driver(drivers: &[TtyDriver], major: u64, minor: u64) -> Option<&TtyDriver> {
    for d in drivers {
        if major == d.major as u64 && d.minor_first as u64 <= minor && minor <= d.minor_last as u64
        {
            return Some(d);
        }
    }
    None
}

async fn link_name(major: u64, minor: u64, pid: u32, name: &str) -> Option<PathBuf> {
    let path = format!("/prod/{}/{}", pid, name);
    if let Ok(buf) = fs::read_link(path).await {
        match fs::metadata(&buf).await {
            Ok(m) => {
                if does_rdev_match(m, major, minor) {
                    Some(buf)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    } else {
        None
    }
}

const LOW_DENSITY_NAMES: [&str; 212] = [
    "LU0", "LU1", "LU2", "LU3", "FB0", "SA0", "SA1", "SA2", "SC0", "SC1", "SC2", "SC3", "FW0",
    "FW1", "FW2", "FW3", "AM0", "AM1", "AM2", "AM3", "AM4", "AM5", "AM6", "AM7", "AM8", "AM9",
    "AM10", "AM11", "AM12", "AM13", "AM14", "AM15", "DB0", "DB1", "DB2", "DB3", "DB4", "DB5",
    "DB6", "DB7", "SG0", "SMX0", "SMX1", "SMX2", "MM0", "MM1", "CPM0", "CPM1", "CPM2",
    "CPM3", /* "CPM4", "CPM5", */
    // bad allocation?
    "IOC0", "IOC1", "IOC2", "IOC3", "IOC4", "IOC5", "IOC6", "IOC7", "IOC8", "IOC9", "IOC10",
    "IOC11", "IOC12", "IOC13", "IOC14", "IOC15", "IOC16", "IOC17", "IOC18", "IOC19", "IOC20",
    "IOC21", "IOC22", "IOC23", "IOC24", "IOC25", "IOC26", "IOC27", "IOC28", "IOC29", "IOC30",
    "IOC31", "VR0", "VR1", "IOC84", "IOC85", "IOC86", "IOC87", "IOC88", "IOC89", "IOC90", "IOC91",
    "IOC92", "IOC93", "IOC94", "IOC95", "IOC96", "IOC97", "IOC98", "IOC99", "IOC100", "IOC101",
    "IOC102", "IOC103", "IOC104", "IOC105", "IOC106", "IOC107", "IOC108", "IOC109", "IOC110",
    "IOC111", "IOC112", "IOC113", "IOC114", "IOC115", "SIOC0", "SIOC1", "SIOC2", "SIOC3", "SIOC4",
    "SIOC5", "SIOC6", "SIOC7", "SIOC8", "SIOC9", "SIOC10", "SIOC11", "SIOC12", "SIOC13", "SIOC14",
    "SIOC15", "SIOC16", "SIOC17", "SIOC18", "SIOC19", "SIOC20", "SIOC21", "SIOC22", "SIOC23",
    "SIOC24", "SIOC25", "SIOC26", "SIOC27", "SIOC28", "SIOC29", "SIOC30", "SIOC31", "PSC0", "PSC1",
    "PSC2", "PSC3", "PSC4", "PSC5", "AT0", "AT1", "AT2", "AT3", "AT4", "AT5", "AT6", "AT7", "AT8",
    "AT9", "AT10", "AT11", "AT12", "AT13", "AT14", "AT15", "NX0", "NX1", "NX2", "NX3", "NX4",
    "NX5", "NX6", "NX7", "NX8", "NX9", "NX10", "NX11", "NX12", "NX13", "NX14", "NX15",
    "J0", // minor is 186
    "UL0", "UL1", "UL2", "UL3", "xvc0", // FAIL -- "/dev/xvc0" lacks "tty" prefix
    "PZ0", "PZ1", "PZ2", "PZ3", "TX0", "TX1", "TX2", "TX3", "TX4", "TX5", "TX6", "TX7", "SC0",
    "SC1", "SC2", "SC3", "MAX0", "MAX1", "MAX2", "MAX3",
];

async fn guess_name(major: u64, minor: u64) -> Option<PathBuf> {
    let path = match major {
        4 => {
            if minor < 64 {
                format!("/dev/ttd{}", minor)
            } else {
                format!("/dev/ttyS{}", minor - 64)
            }
        }
        11 => format!("/dev/ttyB{}", minor),
        17 => format!("/dev/ttyH{}", minor),
        19 => format!("/dev/ttyC{}", minor),
        22 => format!("/dev/ttyD{}", minor), // devices.txt
        23 => format!("/dev/ttyD{}", minor), // driver code
        24 => format!("/dev/ttyE{}", minor),
        32 => format!("/dev/ttyX{}", minor),
        43 => format!("/dev/ttyI{}", minor),
        46 => format!("/dev/ttyR{}", minor),
        48 => format!("/dev/ttyL{}", minor),
        57 => format!("/dev/ttyP{}", minor),
        71 => format!("/dev/ttyF{}", minor),
        75 => format!("/dev/ttyW{}", minor),
        78 => format!("/dev/ttyM{}", minor), // conflict
        105 => format!("/dev/ttyV{}", minor),
        112 => format!("/dev/ttyM{}", minor), // conflict
        // 134-143 are /dev/pts/0, /dev/pts/1, /dev/pts/2 ...
        136..=143 => format!("/dev/pts/{}", minor + (major - 136) * 256),
        148 => format!("/dev/ttyT{}", minor),
        154 => format!("/dev/ttySR{}", minor),
        156 => format!("/dev/ttySR{}", minor + 256),
        164 => format!("/dev/ttyCH{}", minor),
        166 => format!("/dev/ttyACM{}", minor), // 9-char
        172 => format!("/dev/ttyMX{}", minor),
        174 => format!("/dev/ttySI{}", minor),
        188 => format!("/dev/ttyUSB{}", minor), // 9-char
        204 => format!(
            "/dev/tty{}",
            LOW_DENSITY_NAMES[usize::try_from(minor).unwrap()]
        ),
        208 => format!("/dev/ttyU{}", minor),
        216 => format!("/dev/ttyUB{}", minor), // "/dev/rfcomm%d" now?
        224 => format!("/dev/ttyY{}", minor),
        227 => format!("/dev/3270/tty{}", minor),
        229 => format!("/dev/iseries/vtty{}", minor),
        256 => format!("/dev/ttyEQ{}", minor),
        _ => return None,
    };
    match fs::metadata(&path).await {
        Ok(m) => {
            if does_rdev_match(m, major, minor) {
                Some(PathBuf::from(path))
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

mod test {
    use super::*;

    #[test]
    fn test_read_tty_drivers() {
        let mut bytes = b"/dev/tty             /dev/tty        5       0 system:/dev/tty\n\
        serial               /dev/ttyS       4 64-111 serial\n\
        for_test             /dev/tty/%d     4 1-63 console\n"
            .to_vec();
        let cursor = smol::io::Cursor::new(&mut bytes);
        let reader = smol::io::BufReader::new(cursor);
        let wanted = vec![
            TtyDriver {
                name: String::from("tty"),
                major: 5,
                minor_first: 0,
                minor_last: 0,
                is_devfs: false,
            },
            TtyDriver {
                name: String::from("ttyS"),
                major: 4,
                minor_first: 64,
                minor_last: 111,
                is_devfs: false,
            },
            TtyDriver {
                name: String::from("tty/"),
                major: 4,
                minor_first: 1,
                minor_last: 63,
                is_devfs: true,
            },
        ];
        smol::block_on(async {
            let records = read_tty_drivers(reader).await.unwrap();
            assert_eq!(records, wanted);
        });
    }
}
