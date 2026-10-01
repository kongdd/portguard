use super::*;
fn record(message: &str, ssh: bool, time: u64) -> String {
    serde_json::json!({"MESSAGE":message,"SYSLOG_IDENTIFIER":if ssh {"sshd"} else {"kernel"},"_TRANSPORT":if ssh {"syslog"} else {"kernel"},"__REALTIME_TIMESTAMP":(time*1_000_000).to_string()}).to_string()
}
#[test]
fn windows() {
    assert_eq!(parse_window("24h").unwrap(), 86400);
    for text in [
        "0h",
        "31d",
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
