use super::*;
fn message_time(message: &str) -> u64 {
    // Slight offset so the `last` ordering remains deterministic across fixtures.
    if message.contains("Accepted publickey for kong from 192.0.2.2") {
        110
    } else {
        100
    }
}

fn record(message: &str, ssh: bool, time: u64) -> String {
    serde_json::json!({"MESSAGE":message,"SYSLOG_IDENTIFIER":if ssh {"sshd"} else {"kernel"},"_TRANSPORT":if ssh {"syslog"} else {"kernel"},"__REALTIME_TIMESTAMP":(time*1_000_000).to_string()}).to_string()
}
#[test]
fn table_aligns_english_ipv6_counts_ports_and_recent_time() {
    let first = Entry {
        ip: "192.0.2.1".into(),
        ssh_failures: 2,
        denied_packets_logged: 43,
        last_seen_unix: 99_999,
        ..Entry::default()
    };
    let second = Entry {
        ip: "2001:db8:abcd:1234:5678:90ab:cdef:1234".into(),
        ssh_failures: 123_456_789,
        destination_ports: [22, 443, 5202, 65535].into_iter().collect(),
        last_seen_unix: 1,
        ..Entry::default()
    };
    let table = render_table(&[&first, &second], 100_000);
    assert!(!table.contains('\t'));
    assert!(table.is_ascii());
    let lines: Vec<_> = table.lines().collect();
    assert_eq!(lines.len(), 4);
    let width = lines[0].len();
    assert!(lines.iter().all(|line| line.len() == width));
    let header: Vec<_> = lines[0].split(" | ").collect();
    for line in &lines[2..] {
        let cells: Vec<_> = line.split(" | ").collect();
        assert_eq!(cells.len(), header.len());
        for (cell, label) in cells.iter().zip(&header) {
            assert_eq!(cell.len(), label.len());
        }
    }
    assert_eq!(header.len(), 9);
    assert_eq!(header[7].trim(), "drop");
    assert_eq!(lines[2].split(" | ").nth(7).unwrap(), "  43");
    assert_eq!(lines[2].split(" | ").nth(2).unwrap(), "        2");
    assert_eq!(lines[2].split(" | ").last().unwrap(), "1 sec ");
    assert_eq!(lines[3].split(" | ").last().unwrap(), "1 day ");
    let empty = render_table(&[], 100_000);
    let lines: Vec<_> = empty.lines().collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0].len(), lines[1].len());
}

#[test]
fn chinese_addresses_keep_table_columns_aligned() {
    let first = Entry {
        ip: "1.1.1.1".into(),
        address: "广东省 / 深圳市".into(),
        ..Entry::default()
    };
    let second = Entry {
        ip: "81.70.146.20".into(),
        address: "很长很长很长很长的省份 / 很长很长很长的城市".into(),
        ..Entry::default()
    };
    let table = render_table(&[&first, &second], 100);
    let lines: Vec<_> = table.lines().collect();
    let width = lines[0].width();
    assert!(lines.iter().all(|line| line.width() == width));
    for line in &lines[2..] {
        let cells: Vec<_> = line.split(" | ").collect();
        assert_eq!(cells[1].width(), short_address(&second.address).width());
        assert!(cells[1].width() <= 24);
        assert!(cells[1].starts_with(if line == &lines[2] {
            "广东省"
        } else {
            "很长"
        }));
    }
    assert!(lines[3].contains('…'));
    assert!(!second.address.contains('…')); // Only table output is shortened.
}

#[test]
fn age_units_and_boundaries() {
    for (seconds, expected) in [
        (0, "0 sec"),
        (59, "59 sec"),
        (60, "1 min"),
        (3599, "59 min"),
        (3600, "1 hour"),
        (86399, "23 hour"),
        (86400, "1 day"),
        (2591999, "29 day"),
        (2592000, "1 mon"),
        (5184000, "2 mon"),
        (365 * 86400, "12 mon"),
    ] {
        let (number, unit) = age_parts(seconds);
        assert_eq!(format!("{number} {unit}"), expected);
    }
    let future = Entry {
        last_seen_unix: 101,
        ..Entry::default()
    };
    assert!(render_table(&[&future], 100).trim_end().ends_with("0 sec"));
}

#[test]
fn last_numbers_and_units_align_independently() {
    let timestamp = 10_000_000;
    let entries: Vec<_> = [59, 300, 3600, 172800, 2592000]
        .into_iter()
        .map(|age| Entry {
            last_seen_unix: timestamp - age,
            ..Entry::default()
        })
        .collect();
    let refs: Vec<_> = entries.iter().collect();
    let table = render_table(&refs, timestamp);
    let last: Vec<_> = table
        .lines()
        .skip(2)
        .map(|line| line.split(" | ").last().unwrap())
        .collect();
    assert_eq!(
        last,
        ["59 sec ", " 5 min ", " 1 hour", " 2 day ", " 1 mon "]
    );
}

#[test]
fn windows() {
    assert_eq!(parse_window("24h").unwrap(), 86400);
    assert_eq!(parse_window("31d").unwrap(), 31 * 86400);
    assert_eq!(parse_window("365d").unwrap(), 365 * 86400);
    assert_eq!(parse_window("1y").unwrap(), 365 * 86400);
    assert_eq!(parse_window("8760h").unwrap(), 365 * 86400);
    assert_eq!(parse_window("525600m").unwrap(), 365 * 86400);
    for text in [
        "0h",
        "0y",
        "366d",
        "2y",
        "8761h",
        "525601m",
        "-1h",
        "1;echo x",
        "999999999999999999999d",
        "",
        "中文",
    ] {
        assert!(parse_window(text).is_err());
    }
}
#[test]
fn failed_password_publickey_and_success() {
    let mut s = Summary::default();
    for message in [
        "Failed password for invalid user root from 192.0.2.1 port 43000 ssh2",
        "Failed publickey for root from 192.0.2.1 port 43000 ssh2",
        "Accepted publickey for root from 192.0.2.1 port 43000 ssh2",
        "Invalid user root from 192.0.2.1 port 43000",
        "pam_unix(sshd:auth): authentication failure; rhost=192.0.2.1",
    ] {
        s.consume(&record(message, true, 100), 0, 200);
    }
    let e = &s.entries[&"192.0.2.1".parse().unwrap()];
    assert_eq!(e.ssh_failures, 2);
    assert_eq!(e.ssh_successes, 1);
    assert_eq!(e.ssh_invalid_users, 1);
}
#[test]
fn connection_samples_and_ranking() {
    let mut s = Summary::default();
    for message in [
        "Connection reset by 81.70.146.20 port 55624 [preauth]",
        "Connection closed by 81.70.146.20 port 36602",
        "Connection closed by authenticating user root 81.70.146.20 port 44438 [preauth]",
        "Connection closed by invalid user bad from 1.1.1.1 81.70.146.20 port 44439 [preauth]",
        "error: kex_exchange_identification: read: Connection reset by peer",
        "Accepted publickey for kong from 192.0.2.2 port 1234 ssh2",
        "Failed password for root from 192.0.2.1 port 1234 ssh2",
    ] {
        s.consume(&record(message, true, message_time(message)), 0, 200);
    }
    let e = &s.entries[&"81.70.146.20".parse().unwrap()];
    assert_eq!(e.ssh_connection_closed, 3);
    assert_eq!(e.ssh_connection_reset, 1);
    assert_eq!(e.ssh_failures, 0);
    assert_eq!(e.ssh_invalid_users, 0);
    assert_eq!(s.entries.len(), 3);
    let mut options = Options {
        since: 86400,
        limit: 20,
        ip: None,
        min_events: 1,
        json: false,
        no_geo: true,
        geo_cache: None,
        no_index: true,
        index_path: None,
        action: None,
        sort: "fail".into(),
    };
    let entries = ranked(&s, &options).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].ip, "192.0.2.1");
    assert_eq!(entries[1].ip, "81.70.146.20");
    options.min_events = 4;
    assert_eq!(ranked(&s, &options).unwrap()[0].ip, "81.70.146.20");
    options.min_events = 0;
    let entries = ranked(&s, &options).unwrap();
    assert_eq!(entries.len(), 3);
    options.ip = Some("81.70.146.20".parse().unwrap());
    options.limit = 1;
    assert_eq!(ranked(&s, &options).unwrap().len(), 1);
    options.ip = None;
    options.limit = 20;
    options.sort = "invalid".into();
    let invalid_order = ranked(&s, &options).unwrap();
    // 192.0.2.1 has 1 invalid user, others have 0; it must be first.
    assert_eq!(invalid_order[0].ip, "192.0.2.1");
    options.sort = "last".into();
    let last_order = ranked(&s, &options).unwrap();
    // 192.0.2.2 was recorded with time=110, others at time=100.
    assert_eq!(last_order[0].ip, "192.0.2.2");
    options.sort = "reset".into();
    assert!(ranked(&s, &options).unwrap().len() >= 2);
    for bad in ["FAIL", "", "auth", "ip_address", "ports"] {
        options.sort = bad.into();
        assert!(ranked(&s, &options).is_err(), "expected error for {bad}");
    }
    options.sort = "fail".into();
}

#[test]
fn connection_parser_ipv6_mapped_and_invalid_suffixes() {
    for (message, ip) in [
        (
            "Connection closed by invalid user root 2001:db8::1 port 1234 [preauth]",
            "2001:db8::1",
        ),
        (
            "Connection reset by ::ffff:192.0.2.1 port 1234",
            "192.0.2.1",
        ),
    ] {
        assert_eq!(connection_ip(message).unwrap().to_string(), ip);
    }
    for message in [
        "Connection reset by peer",
        "Connection closed by 192.0.2.1 port invalid",
        "Connection closed by 192.0.2.1 port 65536",
        "Connection closed by not-an-ip port 1234",
    ] {
        assert!(connection_ip(message).is_none());
    }
    let mut s = Summary::default();
    s.consume(
        &record("Connection reset by 192.0.2.1 port 1234", false, 100),
        0,
        200,
    );
    assert!(s.entries.is_empty());
}

#[test]
fn ipv6_kernel_and_untrusted_messages() {
    let mut s = Summary::default();
    s.consume(
        &record(
            "portguard DROP IN=eth0 SRC=2001:db8::1 DST=2001:db8::2 PROTO=TCP SPT=1234 DPT=5202",
            false,
            150,
        ),
        0,
        200,
    );
    for message in [
        record(
            "Failed password for root from 2001:db8::1 port 43000 ssh2",
            false,
            150,
        ),
        record("portguard DROP SRC=192.0.2.1 DPT=5202", true, 150),
    ] {
        s.consume(&message, 0, 200);
    }
    assert_eq!(s.entries.len(), 1);
    let e = &s.entries[&"2001:db8::1".parse().unwrap()];
    assert_eq!(e.denied_packets_logged, 1);
    assert!(e.destination_ports.contains(&5202));
    assert_eq!(e.ssh_failures, 0);
}
#[test]
fn window_order_and_bad_logs() {
    let mut s = Summary::default();
    let message = "Failed password for root from 192.0.2.1 port 1234 ssh2";
    for time in [50, 250, 180, 110] {
        s.consume(&record(message, true, time), 100, 200);
    }
    s.consume("not JSON", 100, 200);
    assert_eq!(s.entries.len(), 1);
    assert_eq!(s.malformed_records, 1);
    let e = &s.entries[&"192.0.2.1".parse().unwrap()];
    assert_eq!(e.first_seen_unix, 110);
    assert_eq!(e.last_seen_unix, 180);
}
#[test]
fn username_does_not_inject_source_ip() {
    let message = "Failed password for invalid user bad from 1.1.1.1 from 192.0.2.1 port 1234 ssh2";
    assert_eq!(ssh_ip(message).unwrap().to_string(), "192.0.2.1");
}
