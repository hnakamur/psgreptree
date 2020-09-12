use regex::Regex;
use smol::fs::File;
use smol::io::BufReader;
use smol::prelude::{AsyncBufReadExt, AsyncReadExt, StreamExt};
use std::io::Result;

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct TtyDriver {
    name: String,
    major: i32,
    minor_first: i32,
    minor_last: i32,
    is_devfs: bool,
}

pub async fn load_tty_drivers() -> Result<Vec<TtyDriver>> {
    let file = File::open("/proc/tty/drivers").await?;
    read_tty_drivers(BufReader::new(file)).await
}

async fn read_tty_drivers<R: AsyncReadExt + Unpin>(
    reader: BufReader<R>,
) -> Result<Vec<TtyDriver>> {
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
