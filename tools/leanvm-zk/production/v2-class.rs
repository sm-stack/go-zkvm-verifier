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

/// Each leaf class's program bounds, in class order: the padded bytecode, the RAM and the advice
/// as base-two logarithms of words, the padded image's words, and the most members one leaf
/// publishes.
pub const CLASS_BOUNDS: [[usize; 5]; 2] = [[12, 17, 13, 64, 128], [13, 17, 16, 64, 128]];

/// Each leaf class's table heights, as base-two logarithms of rows, in leanVM's table order: ALU,
/// LOAD, STORE, LD, SD, SHIFT, MUL, MULH, DIV, HASH, EXT.
///
/// The program class fits small general programs, up to 2^16 cycles; the signature class fits the
/// signature-member guest over [`SIGNATURES_PER_LEAF`] signatures. Both are below the shared
/// first-level heights the signature class sets.
pub const CLASS_LEAF_HEIGHTS: [[usize; 11]; 2] =
    [[16, 8, 8, 10, 10, 10, 8, 6, 6, 8, 6], [20, 4, 15, 18, 18, 16, 4, 4, 4, 16, 3]];

/// Every leaf proof's and tree proof's commitment rate, as a base-two logarithm of its inverse.
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
    0x59, 0x26, 0xb5, 0xcf, 0x98, 0xb4, 0xe8, 0x56, 0x5b, 0xaa, 0x69, 0x83, 0xe3, 0x0d, 0x15, 0x1e,
    0xec, 0x34, 0x7a, 0xe2, 0x4b, 0xc2, 0xb7, 0xa5, 0x9b, 0xe5, 0x53, 0xe9, 0xba, 0xe9, 0xb5, 0xe8,
];

/// The leaf classes, in class order.
pub fn classes() -> [LeafClass; 2] {
    core::array::from_fn(|i| {
        let [log_bytecode, log_ram, log_advice, image_words, max_members] = CLASS_BOUNDS[i];
        LeafClass {
            program: ProgramClass { log_bytecode, log_ram, log_advice, image_words, max_members },
            shape: LeafShape::plain(
                PerTable::from_fn(|t: TableId| CLASS_LEAF_HEIGHTS[i][t.index()]),
                rate(),
            )
            .expect("the classes' leaf heights are valid"),
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
