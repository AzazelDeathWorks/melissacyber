use aegis_kg::*;

#[test]
fn add_node_and_frontier() {
    let mut kg = KnowledgeGraph::default();
    let id = kg.add_node(Node {
        id: uuid::Uuid::new_v4(),
        kind: NodeKind::Endpoint,
        label: "ep".into(),
        data: serde_json::json!({"url": "http://a"}),
        provenance: None,
    });
    assert_eq!(kg.nodes().count(), 1);
    assert_eq!(kg.get(&id).unwrap().label, "ep");
}

#[test]
fn save_and_reload() {
    let mut kg = KnowledgeGraph::default();
    kg.add_node(Node {
        id: uuid::Uuid::new_v4(),
        kind: NodeKind::Asset,
        label: "t".into(),
        data: serde_json::json!({}),
        provenance: None,
    });
    let dir = std::env::temp_dir().join(format!("aegis-kg-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("kg.json");
    kg.save(&p).unwrap();
    assert!(p.exists());
}
