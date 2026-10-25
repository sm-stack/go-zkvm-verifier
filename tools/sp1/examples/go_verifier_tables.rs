//! Exports SP1 6.8.1 compress constraints, constants and Rust differential vectors.
//! Adapted from Optimism's op-sp1-proofs; see NOTICE and UPSTREAM.md.
//!
//! From the repository root (fixture directory needs decompressed proof.bin):
//! cargo run --locked --release -j 2 --manifest-path tools/sp1/Cargo.toml \
//!     --example go_verifier_tables -- sp1 <fixture directory>
//! gofmt -w sp1/compress_machine_gen.go
//!
//! Prefer `python3 tools/regenerate.py --check` to unpack fixtures and compare in a
//! temporary directory. The fixture key is little-endian bincode [KoalaBear; 8].
//! This generator never produces new proofs.

use alloy_primitives::hex;
use serde::Serialize;
use slop_air::{
    Air, AirBuilder, AirBuilderWithPublicValues, BaseAir, PairBuilder, PairCol, VirtualPairCol,
};
use slop_algebra::{AbstractExtensionField, AbstractField, PrimeField32, TwoAdicField};
use slop_basefold::BATCH_GRINDING_BITS;
use slop_challenger::{CanObserve, CanSampleBits, FieldChallenger, GrindingChallenger, IopCtx};
use slop_koala_bear::{
    KoalaBear_BEGIN_EXT_CONSTS, KoalaBear_END_EXT_CONSTS, KoalaBear_PARTIAL_CONSTS, my_kb_16_perm,
};
use slop_matrix::dense::{RowMajorMatrix, RowMajorMatrixView};
use slop_multilinear::MleEval;
use slop_symmetric::{CryptographicHasher, Permutation, PseudoCompressionFunction};
use slop_uni_stark::{Entry, SymbolicExpression, SymbolicVariable};
use sp1_hypercube::{
    Chip, GKR_GRINDING_BITS, Interaction, MAX_CONSTRAINT_DEGREE, MachineRecord, PROOF_MAX_NUM_PVS,
    UntrustedConfig, VerifierConstraintFolder,
    air::{EmptyMessageBuilder, MachineAir},
};
use sp1_primitives::{
    SP1ExtensionField, SP1Field, SP1GlobalContext, fri_params::recursion_fri_config,
};
use sp1_recursion_executor::{ExecutionRecord, NUM_PV_ELMS_TO_HASH, RecursionPublicValues};
use sp1_recursion_machine::RecursionAir;
use sp1_verifier::{
    SP1Proof, VerifierRecursionVks,
    compressed::{RECURSION_LOG_STACKING_HEIGHT, RECURSION_MAX_LOG_ROW_COUNT},
};
use std::{
    borrow::Borrow, collections::HashMap, fmt::Write as _, marker::PhantomData, mem::size_of,
    path::Path,
};

type F = SP1Field;
type EF = SP1ExtensionField;
/// The compress machine's AIR: `sp1_verifier::compressed::internal::CompressAir`, which is private.
type CompressAir = RecursionAir<F, 3, 2>;

/// Node operations of the exported constraint DAG. The Go interpreter uses the same values.
const OP_CONST: u32 = 0;
const OP_PREPROCESSED: u32 = 1;
const OP_MAIN: u32 = 2;
const OP_PUBLIC: u32 = 3;
const OP_ADD: u32 = 4;
const OP_SUB: u32 = 5;
const OP_NEG: u32 = 6;
const OP_MUL: u32 = 7;

/// A constraint DAG in topological order: every node is `(op, a, b)`, and a node only refers to
/// earlier nodes. Structurally equal nodes are shared.
#[derive(Default)]
struct Dag {
    nodes: Vec<[u32; 3]>,
    index: HashMap<[u32; 3], u32>,
    by_ptr: HashMap<*const SymbolicExpression<F>, u32>,
}

impl Dag {
    fn push(&mut self, node: [u32; 3]) -> u32 {
        if let Some(&i) = self.index.get(&node) {
            return i;
        }
        let i = self.nodes.len() as u32;
        self.nodes.push(node);
        self.index.insert(node, i);
        i
    }

    fn add(&mut self, expr: &SymbolicExpression<F>) -> u32 {
        // The constraints outlive the traversal, so no address is reused for another node.
        let ptr = expr as *const _;
        if let Some(&i) = self.by_ptr.get(&ptr) {
            return i;
        }
        let node = match expr {
            SymbolicExpression::Variable(v) => match v.entry {
                Entry::Preprocessed { offset: 0 } => [OP_PREPROCESSED, v.index as u32, 0],
                Entry::Main { offset: 0 } => [OP_MAIN, v.index as u32, 0],
                Entry::Public => [OP_PUBLIC, v.index as u32, 0],
                entry => panic!("the verifier folder has no {entry:?} variables"),
            },
            SymbolicExpression::Constant(c) => [OP_CONST, c.as_canonical_u32(), 0],
            SymbolicExpression::Add { x, y, .. } => [OP_ADD, self.add(x), self.add(y)],
            SymbolicExpression::Sub { x, y, .. } => [OP_SUB, self.add(x), self.add(y)],
            SymbolicExpression::Neg { x, .. } => [OP_NEG, self.add(x), 0],
            SymbolicExpression::Mul { x, y, .. } => [OP_MUL, self.add(x), self.add(y)],
            other => panic!("the verifier folder cannot evaluate {other:?}"),
        };
        let i = self.push(node);
        self.by_ptr.insert(ptr, i);
        i
    }
}

/// Records a chip's constraints symbolically. `slop_uni_stark::get_symbolic_constraints` cannot be
/// used: its builder labels preprocessed columns as main columns. SP1's own `InteractionBuilder`
/// records interactions the same way.
struct ConstraintRecorder {
    preprocessed: RowMajorMatrix<SymbolicVariable<F>>,
    main: RowMajorMatrix<SymbolicVariable<F>>,
    public_values: Vec<SymbolicVariable<F>>,
    constraints: Vec<SymbolicExpression<F>>,
}

impl ConstraintRecorder {
    /// A recorder for traces of the given widths. The verifier evaluates constraints on a single
    /// row, so only the local row exists here: an AIR reading the next row panics.
    fn new(preprocessed_width: usize, width: usize) -> Self {
        let row = |entry: fn() -> Entry, width: usize| {
            RowMajorMatrix::new(
                (0..width)
                    .map(|index| SymbolicVariable::new(entry(), index))
                    .collect(),
                width,
            )
        };
        Self {
            preprocessed: row(|| Entry::Preprocessed { offset: 0 }, preprocessed_width),
            main: row(|| Entry::Main { offset: 0 }, width),
            public_values: (0..PROOF_MAX_NUM_PVS)
                .map(|index| SymbolicVariable::new(Entry::Public, index))
                .collect(),
            constraints: Vec::new(),
        }
    }

    /// Records the constraints of `chip`.
    fn record(chip: &Chip<F, CompressAir>) -> Vec<SymbolicExpression<F>> {
        let mut recorder = Self::new(chip.preprocessed_width(), chip.width());
        chip.eval(&mut recorder);
        assert_eq!(
            recorder.constraints.len(),
            chip.num_constraints,
            "{}",
            chip.name()
        );
        recorder.constraints
    }
}

impl AirBuilder for ConstraintRecorder {
    type F = F;
    type Expr = SymbolicExpression<F>;
    type Var = SymbolicVariable<F>;
    type M = RowMajorMatrix<SymbolicVariable<F>>;

    fn main(&self) -> Self::M {
        self.main.clone()
    }

    fn is_first_row(&self) -> Self::Expr {
        unimplemented!("the verifier folder has no row selectors")
    }

    fn is_last_row(&self) -> Self::Expr {
        unimplemented!("the verifier folder has no row selectors")
    }

    fn is_transition_window(&self, _: usize) -> Self::Expr {
        unimplemented!("the verifier folder has no row selectors")
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.constraints.push(x.into());
    }
}

impl PairBuilder for ConstraintRecorder {
    fn preprocessed(&self) -> Self::M {
        self.preprocessed.clone()
    }
}

impl AirBuilderWithPublicValues for ConstraintRecorder {
    type PublicVar = SymbolicVariable<F>;

    fn public_values(&self) -> &[Self::PublicVar] {
        &self.public_values
    }
}

impl EmptyMessageBuilder for ConstraintRecorder {}

/// Deterministic test randomness (xorshift64*), so regenerating the vectors is reproducible.
struct Rng(u64);

impl Rng {
    const fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn f(&mut self) -> F {
        F::from_canonical_u32((self.next_u64() % u64::from(F::ORDER_U32)) as u32)
    }

    fn ef(&mut self) -> EF {
        EF::from_base_slice(&[self.f(), self.f(), self.f(), self.f()])
    }
}

fn f_json(x: F) -> String {
    x.as_canonical_u32().to_string()
}

fn fs_json(xs: &[F]) -> String {
    format!(
        "[{}]",
        xs.iter().map(|&x| f_json(x)).collect::<Vec<_>>().join(",")
    )
}

fn ef_json(x: EF) -> String {
    fs_json(x.as_base_slice())
}

fn efs_json(xs: &[EF]) -> String {
    format!(
        "[{}]",
        xs.iter().map(|&x| ef_json(x)).collect::<Vec<_>>().join(",")
    )
}

fn go_u32s(xs: impl IntoIterator<Item = u32>) -> String {
    let xs = xs.into_iter().map(|x| format!("{x},")).collect::<Vec<_>>();
    let lines = xs
        .chunks(24)
        .map(|line| format!("\n\t\t\t{}", line.join(" ")))
        .collect::<String>();
    format!("[]uint32{{{lines}\n\t\t}}")
}

fn go_column(col: &VirtualPairCol<F>) -> String {
    let terms = col
        .column_weights
        .iter()
        .map(|(column, weight)| {
            let (preprocessed, index) = match column {
                PairCol::Preprocessed(i) => (true, *i),
                PairCol::Main(i) => (false, *i),
            };
            format!("{{{preprocessed}, {index}, {}}}", weight.as_canonical_u32())
        })
        .collect::<Vec<_>>()
        .join(", ");
    let terms = if terms.is_empty() {
        "nil".to_owned()
    } else {
        format!("[]columnTerm{{{terms}}}")
    };
    format!("{{{}, {terms}}}", col.constant.as_canonical_u32())
}

fn go_interactions(interactions: &[Interaction<F>]) -> String {
    let mut out = String::from("[]interaction{\n");
    for interaction in interactions {
        let values = interaction
            .values
            .iter()
            .map(go_column)
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(
            out,
            "\t\t\t{{kind: {}, multiplicity: virtualColumn{}, values: []virtualColumn{{{values}}}}},",
            interaction.argument_index(),
            go_column(&interaction.multiplicity),
        )
        .unwrap();
    }
    out.push_str("\t\t}");
    out
}

fn sorted_chips() -> Vec<Chip<F, CompressAir>> {
    let mut chips = CompressAir::compress_machine().chips().to_vec();
    chips.sort_by(|a, b| a.name().cmp(b.name()));
    chips
}

/// Checks what the Go port assumes about the compress machine instead of reading it from here.
fn check_go_assumptions() {
    let machine = CompressAir::compress_machine();
    // No public value beyond the machine's may be nonzero: Go checks only the length.
    assert_eq!(machine.num_pv_elts(), PROOF_MAX_NUM_PVS);
    // A shard proof must open exactly the machine's chips.
    assert_eq!(machine.shape().chip_clusters.len(), 1);
    assert_eq!(
        machine.shape().chip_clusters[0].len(),
        machine.chips().len()
    );
    // The recursion record has no public value constraints or interactions, so Go skips the public
    // value folder and takes their cumulative sum as zero.
    assert!(<ExecutionRecord<F> as MachineRecord>::interactions_in_public_values().is_empty());
    let mut recorder = ConstraintRecorder::new(0, 0);
    <ExecutionRecord<F> as MachineRecord>::eval_public_values(&mut recorder);
    assert!(recorder.constraints.is_empty());
    // sp1-hypercube's `mprotect` feature adds verifying key fields that Go does not read.
    assert_eq!(size_of::<UntrustedConfig<F>>(), size_of::<F>());
}

fn write_machine(dir: &Path) {
    check_go_assumptions();
    let mut go = String::from(
        "// Code generated by tools/sp1/examples/go_verifier_tables.rs. DO NOT EDIT.\n\npackage sp1\n\n",
    );
    go.push_str("// compressChips are the compress machine's chips, sorted by name.\n");
    go.push_str("var compressChips = []chipAir{\n");
    let mut total_nodes = 0;
    for chip in sorted_chips() {
        let constraints = ConstraintRecorder::record(&chip);
        let mut dag = Dag::default();
        let roots = constraints.iter().map(|c| dag.add(c)).collect::<Vec<_>>();
        total_nodes += dag.nodes.len();
        eprintln!(
            "{}: {} constraints, {} nodes, {} sends, {} receives",
            chip.name(),
            roots.len(),
            dag.nodes.len(),
            chip.sends().len(),
            chip.receives().len()
        );
        writeln!(
            go,
            "\t{{\n\t\tname: {:?},\n\t\tpreprocessedWidth: {},\n\t\twidth: {},\n\t\tnodes: {},\n\t\tconstraints: {},\n\t\tsends: {},\n\t\treceives: {},\n\t}},",
            chip.name(),
            chip.preprocessed_width(),
            chip.width(),
            go_u32s(dag.nodes.iter().flatten().copied()),
            go_u32s(roots),
            go_interactions(chip.sends()),
            go_interactions(chip.receives()),
        )
        .unwrap();
    }
    go.push_str("}\n\n");
    eprintln!("total nodes: {total_nodes}");

    let fri = recursion_fri_config();
    let vks = VerifierRecursionVks::default();
    let indices: [F; PROOF_MAX_NUM_PVS] = core::array::from_fn(F::from_canonical_usize);
    let pv: &RecursionPublicValues<F> = indices.as_slice().borrow();
    let offset = |x: &F| x.as_canonical_u32();
    writeln!(
        go,
        "const (
\tnumPublicValues    = {PROOF_MAX_NUM_PVS}
\tmaxLogRowCount     = {RECURSION_MAX_LOG_ROW_COUNT}
\tlogStackingHeight  = {RECURSION_LOG_STACKING_HEIGHT}
\tmaxConstraintDeg   = {MAX_CONSTRAINT_DEGREE}
\tgkrGrindingBits    = {GKR_GRINDING_BITS}
\tbatchGrindingBits  = {}
\tfriLogBlowup       = {}
\tfriNumQueries      = {}
\tfriProofOfWorkBits = {}
\tvkNumKeys          = {}

\t// Offsets of the recursion public values the verifier reads.
\tpvCommittedValueDigest = {}
\tpvSP1VkDigest          = {}
\tpvVkRoot               = {}
\tpvIsComplete           = {}
\tpvDigest               = {}
\tpvNumHashed            = {NUM_PV_ELMS_TO_HASH}
)
",
        BATCH_GRINDING_BITS,
        fri.log_blowup,
        fri.num_queries,
        fri.proof_of_work_bits,
        vks.num_keys(),
        offset(&pv.committed_value_digest[0][0]),
        offset(&pv.sp1_vk_digest[0]),
        offset(&pv.vk_root[0]),
        offset(&pv.is_complete),
        offset(&pv.digest[0]),
    )
    .unwrap();
    writeln!(
        go,
        "// vkMerkleRoot is the root of the Merkle tree of the recursion verifying keys a compress\n// proof may use.\nvar vkMerkleRoot = digestFromU32s({})\n",
        go_u32s(vks.root().map(|x| x.as_canonical_u32()))
    )
    .unwrap();
    writeln!(
        go,
        "// twoAdicGenerators[i] generates the multiplicative subgroup of order 2^i.\nvar twoAdicGenerators = {}\n",
        go_u32s((0..=F::TWO_ADICITY).map(|i| F::two_adic_generator(i).as_canonical_u32()))
    )
    .unwrap();
    writeln!(
        go,
        "// poseidon2ExternalConstants are the round constants of the four initial and four final\n// full rounds.\nvar poseidon2ExternalConstants = {}\n",
        go_u32s(
            KoalaBear_BEGIN_EXT_CONSTS
                .iter()
                .chain(KoalaBear_END_EXT_CONSTS.iter())
                .flatten()
                .map(|x| x.as_canonical_u32())
        )
    )
    .unwrap();
    writeln!(
        go,
        "// poseidon2InternalConstants are the round constants of the partial rounds.\nvar poseidon2InternalConstants = {}",
        go_u32s(KoalaBear_PARTIAL_CONSTS.iter().map(|x| x.as_canonical_u32()))
    )
    .unwrap();
    std::fs::write(dir.join("compress_machine_gen.go"), go).unwrap();
}

fn write_vectors(dir: &Path) {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut json = String::from("{\n");

    // Poseidon2 permutation.
    let perm = my_kb_16_perm();
    let mut cases = Vec::new();
    for _ in 0..3 {
        let input: [F; 16] = core::array::from_fn(|_| rng.f());
        let output = perm.permute(input);
        cases.push(format!(
            "{{\"in\":{},\"out\":{}}}",
            fs_json(&input),
            fs_json(&output)
        ));
    }
    writeln!(json, "\"permutation\":[{}],", cases.join(",")).unwrap();

    // Sponge and compression.
    let (hasher, compressor) = SP1GlobalContext::default_hasher_and_compressor();
    let mut cases = Vec::new();
    for len in [0, 1, 7, 8, 9, 16, 26] {
        let input = (0..len).map(|_| rng.f()).collect::<Vec<_>>();
        let output = hasher.hash_iter(input.clone());
        cases.push(format!(
            "{{\"in\":{},\"out\":{}}}",
            fs_json(&input),
            fs_json(&output)
        ));
    }
    writeln!(json, "\"hash\":[{}],", cases.join(",")).unwrap();
    let left: [F; 8] = core::array::from_fn(|_| rng.f());
    let right: [F; 8] = core::array::from_fn(|_| rng.f());
    let output = compressor.compress([left, right]);
    writeln!(
        json,
        "\"compress\":{{\"left\":{},\"right\":{},\"out\":{}}},",
        fs_json(&left),
        fs_json(&right),
        fs_json(&output)
    )
    .unwrap();

    // Extension field arithmetic.
    let mut cases = Vec::new();
    for _ in 0..4 {
        let (a, b) = (rng.ef(), rng.ef());
        cases.push(format!(
            "{{\"a\":{},\"b\":{},\"mul\":{},\"div\":{}}}",
            ef_json(a),
            ef_json(b),
            ef_json(a * b),
            ef_json(a / b)
        ));
    }
    writeln!(json, "\"ext\":[{}],", cases.join(",")).unwrap();

    // Challenger: a fixed script of observations and samples.
    let mut challenger = SP1GlobalContext::default_challenger();
    let mut outputs = Vec::new();
    for i in 0..5u32 {
        challenger.observe(F::from_canonical_u32(i));
    }
    let e: EF = challenger.sample_ext_element();
    outputs.push(ef_json(e));
    challenger.observe([F::from_canonical_u32(7); 8]);
    let e: EF = challenger.sample_ext_element();
    outputs.push(ef_json(e));
    let e: EF = challenger.sample_ext_element();
    outputs.push(ef_json(e));
    outputs.push(format!("[{}]", challenger.sample_bits(22)));
    for i in 0..13u32 {
        challenger.observe(F::from_canonical_u32(100 + i));
    }
    outputs.push(format!("[{}]", challenger.sample_bits(10)));
    // A sequential search: `grind` searches in parallel, so its witness varies between runs.
    let witness = (0..F::ORDER_U32)
        .map(F::from_canonical_u32)
        .find(|witness| challenger.clone().check_witness(8, *witness))
        .unwrap();
    assert!(challenger.check_witness(8, witness));
    outputs.push(format!("[{}]", witness.as_canonical_u32()));
    let e: EF = challenger.sample_ext_element();
    outputs.push(ef_json(e));
    writeln!(json, "\"challenger\":[{}],", outputs.join(",")).unwrap();

    // Constraint and interaction evaluation, chip by chip, through the Rust verifier's folder.
    let mut cases = Vec::new();
    for chip in sorted_chips() {
        let alpha = rng.ef();
        let public_values = (0..PROOF_MAX_NUM_PVS).map(|_| rng.f()).collect::<Vec<_>>();
        let preprocessed = (0..chip.preprocessed_width())
            .map(|_| rng.ef())
            .collect::<Vec<_>>();
        let main = (0..chip.width()).map(|_| rng.ef()).collect::<Vec<_>>();
        let eval = |preprocessed: &[EF], main: &[EF]| {
            let mut folder = VerifierConstraintFolder::<F, EF> {
                preprocessed: RowMajorMatrixView::new_row(preprocessed),
                main: RowMajorMatrixView::new_row(main),
                alpha,
                accumulator: EF::zero(),
                public_values: &public_values,
                _marker: PhantomData,
            };
            chip.eval(&mut folder);
            folder.accumulator
        };
        let value = eval(&preprocessed, &main);
        let zero_value = eval(
            &vec![EF::zero(); preprocessed.len()],
            &vec![EF::zero(); main.len()],
        );

        // As many betas as the verifier samples for the machine's widest interaction.
        let arity = sorted_chips()
            .iter()
            .flat_map(|chip| chip.sends().iter().chain(chip.receives()))
            .map(|interaction| interaction.values.len() + 1)
            .max()
            .unwrap();
        let betas = (0..arity.next_power_of_two())
            .map(|_| rng.ef())
            .collect::<Vec<_>>();
        let preprocessed_eval = MleEval::from(preprocessed.clone());
        let main_eval = MleEval::from(main.clone());
        let preprocessed_eval = (!preprocessed.is_empty()).then_some(&preprocessed_eval);
        let interactions = chip
            .sends()
            .iter()
            .chain(chip.receives())
            .map(|interaction| {
                let (numerator, denominator) =
                    interaction.eval::<EF, EF>(preprocessed_eval, &main_eval, alpha, &betas);
                efs_json(&<[EF; 2]>::from((numerator, denominator)))
            })
            .collect::<Vec<_>>();
        cases.push(format!(
            "{{\"chip\":{:?},\"alpha\":{},\"publicValues\":{},\"preprocessed\":{},\"main\":{},\"value\":{},\"zeroValue\":{},\"betas\":{},\"interactions\":[{}]}}",
            chip.name(),
            ef_json(alpha),
            fs_json(&public_values),
            efs_json(&preprocessed),
            efs_json(&main),
            ef_json(value),
            ef_json(zero_value),
            efs_json(&betas),
            interactions.join(",")
        ));
    }
    writeln!(json, "\"chips\":[{}]", cases.join(",\n")).unwrap();
    json.push_str("}\n");
    std::fs::create_dir_all(dir.join("testdata")).unwrap();
    std::fs::write(dir.join("testdata/vectors.json"), json).unwrap();
}

/// A change to the fixture proof's bytes.
enum Mutation {
    /// Replace `remove` bytes at `at` with `insert`.
    Splice {
        at: usize,
        remove: usize,
        insert: Vec<u8>,
    },
    /// Keep only the first `len` bytes.
    Truncate { len: usize },
}

impl Mutation {
    const fn put(at: usize, bytes: Vec<u8>) -> Self {
        Self::Splice {
            at,
            remove: bytes.len(),
            insert: bytes,
        }
    }

    fn apply(&self, proof: &[u8]) -> Vec<u8> {
        let mut out = proof.to_vec();
        match self {
            Self::Splice { at, remove, insert } => {
                out.splice(*at..*at + remove, insert.iter().copied());
            }
            Self::Truncate { len } => out.truncate(*len),
        }
        out
    }

    fn json(&self) -> String {
        match self {
            Self::Splice { at, remove, insert } => {
                format!(
                    "\"at\":{at},\"remove\":{remove},\"insert\":\"{}\"",
                    hex::encode(insert)
                )
            }
            Self::Truncate { len } => format!("\"truncate\":{len}"),
        }
    }
}

/// The legacy bincode encoding the proof uses.
fn encode<T: Serialize>(value: &T) -> Vec<u8> {
    bincode::serde::encode_to_vec(value, bincode::config::legacy()).unwrap()
}

/// Mutations of the decoder's structural rules, at offsets found by encoding the proof's parts:
/// repeated and reordered map keys (the last value wins and keys are sorted, so the proof stays
/// valid), option tags, UTF-8 and tensor dimensions.
fn structural_mutations(proof: &[u8]) -> Vec<Mutation> {
    let SP1Proof::Compressed(p) =
        sp1_reference::decode_bincode::<SP1Proof>(proof, "proof").unwrap()
    else {
        panic!("the fixture is not a compressed proof")
    };
    let shard = &p.proof;
    let gkr = &shard.logup_gkr_proof;
    let at_gkr = 4 + encode(&p.vk).len() + encode(&shard.public_values).len() + 32;
    let at_gkr_chips = at_gkr
        + encode(&gkr.circuit_output).len()
        + encode(&gkr.round_proofs).len()
        + encode(&gkr.logup_evaluations.point).len();
    let at_openings = at_gkr + encode(gkr).len() + encode(&shard.zerocheck_proof).len();

    let mut mutations = Vec::new();
    let count = |n: usize| (n as u64).to_le_bytes().to_vec();

    // A junk entry under the first chip's name ahead of the real one, in both maps.
    let (name, opening) = shard.opened_values.chips.iter().next().unwrap();
    let mut junk = opening.clone();
    junk.main.local[0] += EF::one();
    let entries = shard.opened_values.chips.len();
    mutations.push(Mutation::Splice {
        at: at_openings,
        remove: 8,
        insert: [count(entries + 1), encode(&(name, &junk))].concat(),
    });
    let (gkr_name, gkr_opening) = gkr.logup_evaluations.chip_openings.iter().next().unwrap();
    let mut gkr_junk = gkr_opening.clone();
    gkr_junk.main_trace_evaluations[0] += EF::one();
    mutations.push(Mutation::Splice {
        at: at_gkr_chips,
        remove: 8,
        insert: [count(entries + 1), encode(&(gkr_name, &gkr_junk))].concat(),
    });
    // The first two chips' openings swapped.
    let mut chips = shard.opened_values.chips.iter();
    let (first, second) = (chips.next().unwrap(), chips.next().unwrap());
    let (first, second) = (encode(&first), encode(&second));
    mutations.push(Mutation::Splice {
        at: at_openings + 8,
        remove: first.len() + second.len(),
        insert: [second, first].concat(),
    });
    // An invalid UTF-8 chip name.
    mutations.push(Mutation::put(at_openings + 16, vec![0xff]));
    // An option tag other than 0 or 1, at the first chip with preprocessed evaluations.
    let mut at = at_gkr_chips + 8;
    for (name, opening) in &gkr.logup_evaluations.chip_openings {
        let at_tag = at + encode(name).len() + encode(&opening.main_trace_evaluations).len();
        if opening.preprocessed_trace_evaluations.is_some() {
            mutations.push(Mutation::put(at_tag, vec![2]));
            break;
        }
        at += encode(&(name, opening)).len();
    }
    // The GKR numerator's dimensions: three and four of them, and products that overflow in one
    // direction (with the storage emptied to match a zero size).
    let numerator = encode(&gkr.circuit_output.numerator);
    let storage = encode(&gkr.circuit_output.numerator.guts().as_slice().to_vec()).len();
    let size = gkr.circuit_output.numerator.guts().sizes()[0] as u64;
    let dims = |dims: &[u64]| {
        [
            count(dims.len()),
            dims.iter().flat_map(|d| d.to_le_bytes()).collect(),
        ]
        .concat()
    };
    for shape in [vec![size, 1, 1], vec![size, 1, 1, 1]] {
        mutations.push(Mutation::Splice {
            at: at_gkr + storage,
            remove: numerator.len() - storage,
            insert: dims(&shape),
        });
    }
    for shape in [[1 << 40, 1 << 40, 0], [0, 1 << 40, 1 << 40]] {
        mutations.push(Mutation::Splice {
            at: at_gkr,
            remove: numerator.len(),
            insert: [count(0), dims(&shape)].concat(),
        });
    }
    mutations
}

/// Mutates the fixture proof in ways the decoder and verifier must judge exactly as Rust does, and
/// records Rust's verdicts. Adding the field order to a canonical element must keep the proof
/// valid, since SP1 reduces field elements while decoding.
fn write_mutations(dir: &Path, fixture: &Path) {
    let read = |name: &str| std::fs::read(fixture.join(name)).unwrap();
    let proof = read("proof.bin");
    let public_values = read("public_values.bin");
    let words = read("vkey_hash.bin");
    let mut vkey_words = [0u32; 8];
    for (word, chunk) in vkey_words.iter_mut().zip(words.chunks_exact(4)) {
        *word = u32::from_le_bytes(chunk.try_into().unwrap());
    }
    let vkey_hash = sp1_reference::vkey_hash_from_words(vkey_words);
    let verifier = sp1_reference::ReferenceVerifier::new();
    verifier
        .verify_with_public_values(vkey_hash, &public_values, &proof)
        .unwrap();

    let mut rng = Rng(0x0dd_b1a5_e5ba_d5ee);
    let mut mutations = structural_mutations(&proof);
    let order = F::ORDER_U32;
    let len = proof.len();
    // The field order added to the word at each aligned offset of the header (enum tag, verifying
    // key, public values) and at sampled offsets of the rest, when it does not overflow.
    let plus_order = |at: usize, mutations: &mut Vec<Mutation>| {
        let word = u32::from_le_bytes(proof[at..at + 4].try_into().unwrap());
        if let Some(bumped) = word.checked_add(order) {
            mutations.push(Mutation::put(at, bumped.to_le_bytes().to_vec()));
        }
    };
    for at in (0..1000).step_by(4) {
        plus_order(at, &mut mutations);
    }
    for _ in 0..150 {
        plus_order((rng.next_u64() as usize) % (len - 4), &mut mutations);
    }
    for _ in 0..150 {
        let at = (rng.next_u64() as usize) % len;
        let bit = 1u8 << (rng.next_u64() % 8);
        mutations.push(Mutation::put(at, vec![proof[at] ^ bit]));
    }
    for _ in 0..60 {
        let at = (rng.next_u64() as usize) % (len - 4);
        let value = match rng.next_u64() % 4 {
            0 => 0,
            1 => order - 1,
            2 => order,
            _ => u32::MAX,
        };
        mutations.push(Mutation::put(at, value.to_le_bytes().to_vec()));
    }
    for _ in 0..20 {
        mutations.push(Mutation::Truncate {
            len: (rng.next_u64() as usize) % len,
        });
    }
    mutations.push(Mutation::Truncate { len: len - 1 });
    mutations.push(Mutation::Splice {
        at: len,
        remove: 0,
        insert: vec![0],
    });

    let lines = mutations
        .iter()
        .map(|mutation| {
            let mutated = mutation.apply(&proof);
            let ok = verifier
                .verify_with_public_values(vkey_hash, &public_values, &mutated)
                .is_ok();
            format!("{{{},\"ok\":{ok}}}", mutation.json())
        })
        .collect::<Vec<_>>();
    std::fs::write(
        dir.join("testdata/mutations.json"),
        format!("[\n{}\n]\n", lines.join(",\n")),
    )
    .unwrap();
}

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = args
        .next()
        .expect("usage: go_verifier_tables <sp1 output dir> [fixture dir]");
    let dir = Path::new(&dir);
    write_machine(dir);
    write_vectors(dir);
    if let Some(fixture) = args.next() {
        write_mutations(dir, Path::new(&fixture));
        write_statements(dir, Path::new(&fixture));
    }
}

// Additional differential statements: the proof is unchanged, only its claimed inputs differ.
fn write_statements(dir: &Path, fixture: &Path) {
    let proof = std::fs::read(fixture.join("proof.bin")).unwrap();
    let pv = std::fs::read(fixture.join("public_values.bin")).unwrap();
    let words = std::fs::read(fixture.join("vkey_hash.bin")).unwrap();
    let words =
        std::array::from_fn(|i| u32::from_le_bytes(words[4 * i..4 * i + 4].try_into().unwrap()));
    let key = sp1_reference::vkey_hash_from_words(words);
    let verifier = sp1_reference::ReferenceVerifier::new();
    let mut wrong_pv = pv.clone();
    wrong_pv[0] ^= 1;
    let mut longer_pv = pv.clone();
    longer_pv.push(0);
    let mut wrong_key = key;
    wrong_key[31] ^= 1;
    let mut noncanonical = key;
    // This would become the valid key if a caller reduced instead of rejecting.
    noncanonical[28..].copy_from_slice(&(words[7] + F::ORDER_U32).to_be_bytes());
    let cases = [
        (key, pv.clone()),
        (key, wrong_pv),
        (key, vec![]),
        (key, longer_pv),
        (wrong_key, pv.clone()),
        (noncanonical, pv),
    ];
    // Hex fields and booleans need no JSON string escaping.
    let records: Vec<_> = cases
        .into_iter()
        .map(|(k, p)| {
            format!(
                "{{\"key\":\"{}\",\"public_values\":\"{}\",\"ok\":{}}}",
                hex::encode(k),
                hex::encode(&p),
                verifier.verify_with_public_values(k, &p, &proof).is_ok()
            )
        })
        .collect();
    std::fs::write(
        dir.join("testdata/statements.json"),
        format!("[{}]\n", records.join(",\n")),
    )
    .unwrap();
}
