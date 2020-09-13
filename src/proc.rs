pub mod stat;
pub mod status;

use smol::fs;
use std::str;

pub async fn get_pid_digits() -> usize {
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

fn column_width_for_u32(n: u32) -> usize {
    let mut width = 1;
    let mut n = n / 10;
    while n > 0 {
        width += 1;
        n /= 10;
    }
    width
}

mod test {
    use super::*;

    #[test]
    fn test_column_width_for_u32() {
        assert_eq!(column_width_for_u32(0), 1);
        assert_eq!(column_width_for_u32(1), 1);
        assert_eq!(column_width_for_u32(9), 1);
        assert_eq!(column_width_for_u32(10), 2);
        assert_eq!(column_width_for_u32(99), 2);
        assert_eq!(column_width_for_u32(100), 3);
    }
}
