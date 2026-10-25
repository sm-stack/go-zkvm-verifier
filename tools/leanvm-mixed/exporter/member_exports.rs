// Fixture I/O only; every upstream attack assertion remains enabled.
fn go_port_dump(name: &str, root: &TreeProof, claims: &ClaimSet, seal: &fiat_shamir::ProofTranscript) {
    let f=fixture();
    let out=std::path::PathBuf::from(std::env::var("GO_PORT_ATTACK_DIR").unwrap());
    let dir=out.join(name); std::fs::create_dir_all(&dir).unwrap();
    let roots=f.tree.seal_prover().unwrap().roots();
    let key=f.tree.mixed_verifier_bytes(&roots).unwrap();
    std::fs::write(out.join("class-key.bin"),&key).unwrap();
    let digest=Tree::mixed_class_key_digest(&key);
    std::fs::write(out.join("class-key.digest"),digest.iter().map(|b|format!("{b:02x}")).collect::<String>()).unwrap();
    std::fs::write(dir.join("root.bin"),root.to_bytes()).unwrap();
    std::fs::write(dir.join("claims.bin"),claims.to_bytes()).unwrap();
    std::fs::write(dir.join("seal.bin"),seal.to_bytes()).unwrap();
    let accepts=f.tree.verify_claims_sealed(root,claims,&roots,seal).is_ok();
    let position=f.tree.design.position(root.circuit).unwrap();
    let recursion=f.tree.read(root,position).is_ok();
    std::fs::write(dir.join("verdict.json"),format!("{{\"accept\":{accepts},\"recursion\":{recursion}}}")).unwrap();
}
fn go_port_member_dump(root: &TreeProof, claims: &ClaimSet, seal: &fiat_shamir::ProofTranscript) {
    static INDEX: std::sync::atomic::AtomicUsize=std::sync::atomic::AtomicUsize::new(0);
    let i=INDEX.fetch_add(1,std::sync::atomic::Ordering::Relaxed);
    go_port_dump(&format!("member-{i}"),root,claims,seal);
}
#[test]
fn go_port_export_member_attacks() {
    parallel::init_with_threads(std::num::NonZeroUsize::new(2).unwrap()).unwrap();
    member_classes_fold_deduplicate_close_and_load();
    member_list_forgeries_fail_union_rows_and_both_root_paths();
    leaf_shape_is_bound_by_its_kind_and_fixed_polynomial();
    member_list_rows_match_sdk_for_odd_even_and_empty_boundaries();
    let f=fixture(); let sealer=f.tree.seal_prover().unwrap();
    for i in 0..2 {
        let first=f.first(i); let seal=f.tree.seal(&sealer,&first.proof).unwrap();
        go_port_dump(&format!("valid-class-{i}"),&first.proof,&first.claims,&seal);
    }
}
