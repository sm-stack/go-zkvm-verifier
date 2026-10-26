// The tree class: the library and its build script both include this file, each with its own copy
// of leanVM.

use leanvm::{
    PerTable, Rate, TableId,
    aggregate::{Capacity, ClaimShape, LeafClass, LeafShape, ProgramClass, Tier, TreeShape},
};

/// The leaf class of arbitrary programs, which users prove.
pub const PROGRAM_CLASS: usize = 0;

/// The leaf class of the leanSPHINCS signature-member guest, which the sequencer proves.
pub const SIGNATURE_CLASS: usize = 1;

/// The leaf class of arbitrary programs proven in zero knowledge, which users prove to keep their
/// advice private: the program class's bounds and heights, at a lower rate.
pub const ZK_PROGRAM_CLASS: usize = 2;

/// The number of leaf classes.
pub const CLASSES: usize = 3;

/// Each leaf class's program bounds, in class order: the padded bytecode, the RAM and the advice
/// as base-two logarithms of words, the padded image's words, and the most members one leaf
/// publishes.
pub const CLASS_BOUNDS: [[usize; 5]; CLASSES] =
    [[12, 17, 13, 64, 128], [13, 17, 16, 64, 128], [12, 17, 13, 64, 128]];

/// Each leaf class's table heights, as base-two logarithms of rows, in leanVM's table order: ALU,
/// LOAD, STORE, LD, SD, SHIFT, MUL, MULH, DIV, HASH, EXT.
///
/// The program class fits small general programs, up to 2^16 cycles; the signature class fits the
/// signature-member guest over [`SIGNATURES_PER_LEAF`] signatures. Both are below the shared
/// first-level heights the signature class sets.
pub const CLASS_LEAF_HEIGHTS: [[usize; 11]; CLASSES] = [
    [16, 8, 8, 10, 10, 10, 8, 6, 6, 8, 6],
    [20, 4, 15, 18, 18, 16, 4, 4, 4, 16, 3],
    [16, 8, 8, 10, 10, 10, 8, 6, 6, 8, 6],
];

/// Each leaf class's commitment rate, as a base-two logarithm of its inverse. A zero-knowledge
/// leaf at rate 1/2 is about 530 KB; at 1/4 it is about 425 KB, within the 512 KiB a statement
/// proof may take.
pub const CLASS_LEAF_LOG_INV_RATES: [u8; CLASSES] = [1, 1, 2];

/// Whether each leaf class's proofs are zero knowledge.
pub const CLASS_ZERO_KNOWLEDGE: [bool; CLASSES] = [false, false, true];

/// Every tree proof's commitment rate, as a base-two logarithm of its inverse.
pub const LOG_INV_RATE: u8 = 1;

/// The leaves a first-level node verifies.
pub const ARITY_0: usize = 1;

/// The most children a node above the first level verifies, in either tier.
pub const ARITY: usize = 2;

/// A root declares fewer claims than this.
pub const CLAIM_CAPACITY: usize = 16385;

/// A root declares at most this many groups: distinct programs. Groups cost little: the union
/// reads a header block per group, against one block per two claims.
pub const GROUP_CAPACITY: usize = 1024;

/// A small-tier node declares fewer claims than this; larger unions move to the large tier.
pub const SMALL_CLAIM_CAPACITY: usize = 257;

/// A small-tier node declares at most this many groups. Up to 64 the small tier's circuits keep
/// the heights they have at 16.
pub const SMALL_GROUP_CAPACITY: usize = 64;

/// The most signatures one signature leaf verifies: the guest's advice holds about 104.
pub const SIGNATURES_PER_LEAF: usize = 100;

/// The class key's digest, `BLAKE2s-256(b"leanvm/mixed-class-key/v2" || class key)`: what the
/// class's circuits, fixed polynomials and seal commitments are pinned to.
pub const CLASS_KEY_DIGEST: [u8; 32] = [
    0xce, 0x8d, 0x90, 0x01, 0xf1, 0xe1, 0x04, 0x5f, 0xa8, 0x4b, 0xb6, 0x2c, 0x43, 0x78, 0xe0, 0xcf,
    0xac, 0xe1, 0xcc, 0x09, 0xa9, 0x2c, 0x2c, 0x91, 0xec, 0xe6, 0xf4, 0x40, 0x60, 0x6d, 0x0e, 0x8a,
];

/// The leaf classes, in class order.
pub fn classes() -> [LeafClass; CLASSES] {
    core::array::from_fn(|i| {
        let [log_bytecode, log_ram, log_advice, image_words, max_members] = CLASS_BOUNDS[i];
        let rate = Rate::new(CLASS_LEAF_LOG_INV_RATES[i]).expect("a supported rate");
        let shape = LeafShape::plain(
            PerTable::from_fn(|t: TableId| CLASS_LEAF_HEIGHTS[i][t.index()]),
            rate,
        )
        .expect("the classes' leaf heights are valid");
        LeafClass {
            program: ProgramClass { log_bytecode, log_ram, log_advice, image_words, max_members },
            shape: if CLASS_ZERO_KNOWLEDGE[i] { shape.zero_knowledge() } else { shape },
        }
    })
}

/// The tree shape: the first class's leaf shape, the arities, the rate and both tiers' capacities.
pub fn shape() -> TreeShape {
    TreeShape {
        leaf: classes()[0].shape,
        arity_0: ARITY_0,
        arity: ARITY,
        rate: rate(),
        claims: Some(ClaimShape {
            capacity: Capacity { claims: CLAIM_CAPACITY, groups: GROUP_CAPACITY },
            small: Some(Tier {
                arity: ARITY,
                capacity: Capacity { claims: SMALL_CLAIM_CAPACITY, groups: SMALL_GROUP_CAPACITY },
            }),
        }),
    }
}

fn rate() -> Rate {
    Rate::new(LOG_INV_RATE).expect("a supported rate")
}
