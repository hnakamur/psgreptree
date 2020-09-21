const UNITS: [&str; 9] = ["", "K", "M", "G", "T", "P", "E", "Z", "Y"];

// base: 1024
// max integer part: 3 digits
// floating 
// ceil
pub fn humanize_kbyte(kbyte: u64) -> String {
    let mut unit_index: usize = 1;
    let mut v = kbyte as f64;
    while v >= 1024.0 {
        v /= 1024.0;
        unit_index += 1;
    }
    if v >= 10.0 {
        format!("{}{}", v.ceil(), UNITS[unit_index])
    } else {
        format!("{:.1}{}", (v*10.0).ceil()*0.1, UNITS[unit_index])
    }
}

// base: 1024
// max integer part: 3 digits
// floating 
// ceil
pub fn humanize_byte(byte: u64) -> String {
    let mut unit_index: usize = 0;
    let mut v = byte as f64;
    while v >= 1024.0 {
        v /= 1024.0;
        unit_index += 1;
    }
    if v >= 10.0 {
        format!("{}{}", v.ceil(), UNITS[unit_index])
    } else {
        format!("{:.1}{}", (v*10.0).ceil()*0.1, UNITS[unit_index])
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_humanize_kbyte() {
        assert_eq!(humanize_kbyte(1), "1.0K");
        assert_eq!(humanize_kbyte(999), "999K");
        assert_eq!(humanize_kbyte(1000), "1000K");
        assert_eq!(humanize_kbyte(1023), "1023K");
        assert_eq!(humanize_kbyte(1024), "1.0M");
        assert_eq!(humanize_kbyte(1025), "1.1M");
        assert_eq!(humanize_kbyte(2048), "2.0M");
        assert_eq!(humanize_kbyte(2049), "2.1M");
        assert_eq!(humanize_kbyte(1023 * 1024), "1023M");
        assert_eq!(humanize_kbyte(1023 * 1024 + 1), "1024M");
        assert_eq!(humanize_kbyte(1024 * 1024), "1.0G");
    }

    #[test]
    fn test_humanize_byte() {
        assert_eq!(humanize_byte(1), "1.0");
        assert_eq!(humanize_byte(999), "999");
        assert_eq!(humanize_byte(1000), "1000");
        assert_eq!(humanize_byte(1023), "1023");
        assert_eq!(humanize_byte(1024), "1.0K");
        assert_eq!(humanize_byte(1025), "1.1K");
        assert_eq!(humanize_byte(2048), "2.0K");
        assert_eq!(humanize_byte(2049), "2.1K");
        assert_eq!(humanize_byte(1023 * 1024), "1023K");
        assert_eq!(humanize_byte(1023 * 1024 + 1), "1024K");
        assert_eq!(humanize_byte(1024 * 1024), "1.0M");
    }
}
