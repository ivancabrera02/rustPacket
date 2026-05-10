use std::time::{SystemTime, UNIX_EPOCH};

fn timestamp() -> String {
    // Format: YYYY-MM-DD HH:MM:SS,mmm  
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let total_secs = now.as_secs();
    let millis     = now.subsec_millis();

    // Decompose Unix timestamp into calendar fields 
    let (y, mo, d, h, mi, s) = unix_to_calendar(total_secs);
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02},{:03}", y, mo, d, h, mi, s, millis)
}


fn unix_to_calendar(ts: u64) -> (u32, u32, u32, u32, u32, u32) {
    let s   = ts % 60;
    let ts  = ts / 60;
    let mi  = ts % 60;
    let ts  = ts / 60;
    let h   = ts % 24;
    let mut days = ts / 24; // days since 1970-01-01

    let mut y = 1970u32;
    loop {
        let days_in_year = if is_leap(y) { 366 } else { 365 };
        if days < days_in_year { break; }
        days -= days_in_year;
        y += 1;
    }
    const DAYS_IN_MONTH: [[u64; 12]; 2] = [
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31],
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31],
    ];
    let leap = if is_leap(y) { 1 } else { 0 };
    let mut mo = 0u32;
    for m in 0..12 {
        let dim = DAYS_IN_MONTH[leap][m];
        if days < dim { mo = m as u32 + 1; break; }
        days -= dim;
    }
    (y, mo, days as u32 + 1, h as u32, mi as u32, s as u32)
}

fn is_leap(y: u32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}

pub fn log_info(msg: &str, ts: bool) {
    if ts {
        eprintln!("[{}] [*] {}", timestamp(), msg);
    } else {
        eprintln!("[*] {msg}");
    }
}

pub fn log_error(msg: &str, ts: bool) {
    if ts {
        eprintln!("[{}] [-] {}", timestamp(), msg);
    } else {
        eprintln!("[-] {msg}");
    }
}

pub fn log_debug(msg: &str, ts: bool) {
    if ts {
        eprintln!("[{}] [DEBUG] {}", timestamp(), msg);
    } else {
        eprintln!("[DEBUG] {msg}");
    }
}
