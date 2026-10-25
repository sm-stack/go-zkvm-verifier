// Development-only adapter around the pinned upstream forgery regression.
#[test]
fn go_port_export_forged_wrap() {
    parallel::init_with_threads(std::num::NonZeroUsize::new(2).unwrap()).unwrap();
    let input=std::path::PathBuf::from(std::env::var("GO_PORT_INPUT_DIR").unwrap());
    let bytes=std::fs::read(input.join("class-key.bin")).unwrap();
    let (classes,shape)=go_port_descriptor(&bytes);
    let tree=Tree::mixed_classes(&classes,shape).unwrap();
    let sealer=tree.seal_prover().unwrap();
    let key=tree.mixed_verifier_bytes(&sealer.roots()).unwrap();
    assert_eq!(key,bytes,"same authenticated class");
    let pair=Aggregate{
        proof:TreeProof::from_bytes(&std::fs::read(input.join("wide/root.bin")).unwrap()).unwrap(),
        claims:ClaimSet::from_bytes(&std::fs::read(input.join("wide/claims.bin")).unwrap()).unwrap()
    };
    let mut forged=pair.claims.clone();forged.groups[0].members[0][0]^=1;
    tests::claim_sets::assert_fake_large_wrap_refused(&tree,&pair,&forged);
}
