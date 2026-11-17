use aegis_sandbox::egress::Allowlist;

#[test]
fn ip_literal_tricks_do_not_bypass() {
    let al = Allowlist::new(&["127.0.0.1".to_string(), ".example.com".to_string()]);
    // canonical forms of 127.0.0.1 must all be allowed
    for h in ["127.0.0.1", "127.1", "127.0.1", "0x7f.0.0.1", "2130706433", "0177.0.0.1", "::1", "127.0.0.1."] {
        assert!(al.allows(h), "{h} should normalize to 127.0.0.1");
    }
    // and evil hosts still denied
    assert!(!al.allows("evil.com"));
    assert!(!al.allows("2130706434")); // 127.0.0.2
    // suffix rule
    assert!(al.allows("api.example.com"));
    assert!(!al.allows("example.com.evil.com"));
}
