#[test]
fn import_atomic_converts_to_playbook() {
    let yaml = r#"
name: dump creds
attack_technique: T1003
atomic_tests:
  - name: read shadow
    executor:
      name: sh
      command: cat /etc/shadow
  - name: ls secrets
    executor:
      name: sh
      command: ls /root
"#;
    let doc = aegis_cli::atomic::import_atomic_yaml(yaml).unwrap();
    assert_eq!(doc["technique"], "T1003");
    assert_eq!(doc["steps"].as_array().unwrap().len(), 2);
    assert_eq!(doc["steps"][0]["command"], "cat /etc/shadow");
}
