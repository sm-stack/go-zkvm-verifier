// Development-only adapter around the pinned upstream forgery regression.
#[test]
fn go_port_export_forged_wrap() {
    parallel::init_with_threads(std::num::NonZeroUsize::new(2).unwrap()).unwrap();
    let input=std::path::PathBuf::from(std::env::var("GO_PORT_INPUT_DIR").unwrap());
    let class=ProgramClass{log_bytecode:12,log_ram:4,log_advice:4,image_words:1};
    let hs=[4,4,4,5,5,4,4,4,4,3,3];
    let shape=TreeShape{
        leaf:LeafShape::plain(crate::tables::PerTable::from_fn(|t:crate::tables::TableId| hs[t.index()]),Rate::MIN).unwrap(),
        arity_0:2,arity:2,rate:Rate::MIN,
        claims:Some(ClaimShape{capacity:Capacity{claims:8,groups:4},small:Some(Tier{arity:2,capacity:Capacity{claims:4,groups:2}})})
    };
    let tree=Tree::mixed(class,shape).unwrap();
    let sealer=tree.seal_prover().unwrap();
    let key=tree.mixed_verifier_bytes(&sealer.roots()).unwrap();
    assert_eq!(key,std::fs::read(input.join("class-key.bin")).unwrap(),"same authenticated class");
    let pair=Aggregate{
        proof:TreeProof::from_bytes(&std::fs::read(input.join("wide/root.bin")).unwrap()).unwrap(),
        claims:ClaimSet::from_bytes(&std::fs::read(input.join("wide/claims.bin")).unwrap()).unwrap()
    };
    let mut forged=pair.claims.clone();forged.groups[0].members[0][0]^=1;
    tests::claim_sets::assert_fake_large_wrap_refused(&tree,&pair,&forged);
}
