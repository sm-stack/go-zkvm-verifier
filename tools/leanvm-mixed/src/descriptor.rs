// Decode expected class descriptors for the checked upstream loader. This helper
// is only a vector-tool adapter; the loader still authenticates the entire key.
pub fn descriptor(
    bytes: &[u8],
) -> (
    Vec<leanvm::aggregate::LeafClass>,
    leanvm::aggregate::TreeShape,
) {
    use leanvm::aggregate::{
        Capacity, ClaimShape, LeafClass, LeafShape, ProgramClass, Tier, TreeShape,
    };
    use leanvm::{PerTable, Rate, TableId};
    assert_eq!(&bytes[..8], b"LVMXCK04");
    let mut words = bytes[8..].as_chunks::<8>().0.iter();
    let mut next = || u64::from_le_bytes(*words.next().unwrap()) as usize;
    assert_eq!(next(), 1);
    let n = next();
    let classes: Vec<_> = (0..n)
        .map(|_| {
            let program = ProgramClass {
                log_bytecode: next(),
                log_ram: next(),
                log_advice: next(),
                image_words: next(),
                max_members: next(),
            };
            let heights: [usize; 11] = std::array::from_fn(|_| next());
            let rate = Rate::new(next() as u8).unwrap();
            let kind = next();
            assert!(kind <= 1);
            let shape =
                LeafShape::plain(PerTable::from_fn(|t: TableId| heights[t.index()]), rate).unwrap();
            LeafClass {
                program,
                shape: if kind == 1 {
                    shape.zero_knowledge()
                } else {
                    shape
                },
            }
        })
        .collect();
    let arity_0 = next();
    let arity = next();
    let rate = Rate::new(next() as u8).unwrap();
    let capacity = Capacity {
        claims: next(),
        groups: next(),
    };
    let small = match next() {
        0 => None,
        1 => Some(Tier {
            arity: next(),
            capacity: Capacity {
                claims: next(),
                groups: next(),
            },
        }),
        _ => panic!("tier flag"),
    };
    let shape = TreeShape {
        leaf: classes[0].shape,
        arity_0,
        arity,
        rate,
        claims: Some(ClaimShape { capacity, small }),
    };
    (classes, shape)
}
