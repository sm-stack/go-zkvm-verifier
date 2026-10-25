//! Generates the leanVM Rust verdict/digest corpus from the shipped fixtures.
//! Adapted from Optimism's op-leanvm-proofs; see NOTICE and UPSTREAM.md.
//!
//! From the repository root:
//! cargo run --locked --release -j 2 --manifest-path tools/leanvm/Cargo.toml --example go_vectors
//!
//! STARK_VECTORS_OUT overrides the output JSON path (fixtures remain repository-local).
//! Normal regeneration only verifies existing proofs. Optional proof generation:
//!
//! cargo run --locked --release -j 2 --manifest-path tools/leanvm/Cargo.toml --example go_vectors -- \
//!     prove leanvm/testdata/fibonacci.elf leanvm/testdata/fibonacci-1000 1 1000
//!
//! Preimage fixture: 40000-byte message; advice is its length followed by message words,
//! byte 8i+j = (7i+j) mod 251. Inverse rate is 16 (log inverse rate argument 4).
//! Reproving is expensive and not part of tests or reference checks.

use std::{fmt::Write as _, path::PathBuf};

use leanvm::{Program, Prover, Rate};

/// The fixtures: a guest, a proof of one of its runs and that run's output.
const PROOFS: [(&str, &str); 2] = [
    ("fibonacci.elf", "fibonacci-1000"),
    ("preimage.elf", "preimage-40000"),
];

/// The guests.
const ELFS: [&str; 2] = ["fibonacci.elf", "preimage.elf"];

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => std::fs::write(vectors_path(), vectors()).expect("write the vectors"),
        [cmd, elf, out, rate, advice @ ..] if cmd == "prove" => prove(elf, out, rate, advice),
        _ => panic!(
            "usage: go_vectors [prove <elf> <out prefix> <log inverse rate> <advice word>...]"
        ),
    }
}

/// Proves a run of `elf` on `advice` at the rate `2^-rate` and writes `<out>.proof` and
/// `<out>.output`.
fn prove(elf: &str, out: &str, rate: &str, advice: &[String]) {
    let program = Program::from_elf(&std::fs::read(elf).expect("read the ELF")).expect("a guest");
    let advice: Vec<u64> = advice
        .iter()
        .map(|word| word.parse().expect("an advice word"))
        .collect();
    let rate = Rate::new(rate.parse().expect("a rate")).expect("a supported rate");
    let proved = Prover::new()
        .prove(&program, &advice, rate)
        .expect("a proof");
    println!("{:?}", proved.stats);
    let output: Vec<u8> = proved
        .output
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect();
    std::fs::write(format!("{out}.proof"), proved.proof.to_bytes()).expect("write the proof");
    std::fs::write(format!("{out}.output"), output).expect("write the output");
}

/// Default vector destination: `leanvm/testdata/vectors.json`.
pub(crate) fn vectors_path() -> PathBuf {
    std::env::var_os("STARK_VECTORS_OUT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../leanvm/testdata/vectors.json")
        })
}

/// A fixture from this crate's `testdata`.
fn read(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../leanvm/testdata")
        .join(name);
    std::fs::read(path).unwrap_or_else(|err| panic!("read {name}: {err}"))
}

/// An edit of a file.
#[derive(Clone, Debug)]
enum Edit {
    /// XOR these bytes in at an offset.
    Xor(usize, Vec<u8>),
    /// Replace this many bytes at an offset with these.
    Splice(usize, usize, Vec<u8>),
    /// Keep this many bytes.
    Truncate(usize),
}

impl Edit {
    fn apply(&self, data: &mut Vec<u8>) {
        match self {
            Self::Xor(at, bytes) => {
                for (i, b) in bytes.iter().enumerate() {
                    data[at + i] ^= b;
                }
            }
            Self::Splice(at, remove, insert) => {
                data.splice(*at..at + remove, insert.iter().copied());
            }
            Self::Truncate(len) => data.truncate(*len),
        }
    }

    fn json(&self) -> String {
        match self {
            Self::Xor(at, bytes) => format!("[{at},\"{}\"]", hex(bytes)),
            Self::Splice(at, remove, insert) => format!("[{at},{remove},\"{}\"]", hex(insert)),
            Self::Truncate(len) => format!("[{len}]"),
        }
    }
}

fn xor(at: usize, byte: u8) -> Vec<Edit> {
    vec![Edit::Xor(at, vec![byte])]
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn edited(base: &[u8], edits: &[Edit]) -> Vec<u8> {
    let mut data = base.to_vec();
    for edit in edits {
        edit.apply(&mut data);
    }
    data
}

fn edits_json(edits: &[Edit]) -> String {
    format!(
        "[{}]",
        edits.iter().map(Edit::json).collect::<Vec<_>>().join(",")
    )
}

fn le64(data: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(data[at..at + 8].try_into().unwrap())
}

fn le32(data: &[u8], at: usize) -> u64 {
    u32::from_le_bytes(data[at..at + 4].try_into().unwrap()).into()
}

fn le16(data: &[u8], at: usize) -> usize {
    u16::from_le_bytes(data[at..at + 2].try_into().unwrap()).into()
}

/// Sets the eight bytes at `at` to `value`, as an XOR edit.
fn set64(data: &[u8], at: usize, value: u64) -> Edit {
    let old = le64(data, at);
    Edit::Xor(at, (old ^ value).to_le_bytes().to_vec())
}

/// Sets the four bytes at `at` to `value`, as an XOR edit.
fn set32(data: &[u8], at: usize, value: u32) -> Edit {
    let old = le32(data, at) as u32;
    Edit::Xor(at, (old ^ value).to_le_bytes().to_vec())
}

/// Where a section or a symbol sits in an ELF file.
struct ElfLayout {
    phoff: usize,
    phnum: usize,
    shoff: usize,
    shnum: usize,
    text: (usize, usize),
    data: (usize, usize),
    symtab: (usize, usize),
    strtab: (usize, usize),
    /// The symbol table entries of `__stack_top` and `__advice_top`.
    symbols: [usize; 2],
}

fn elf_layout(elf: &[u8]) -> ElfLayout {
    let (phoff, phnum) = (le64(elf, 32) as usize, le16(elf, 56));
    let (shoff, shnum) = (le64(elf, 40) as usize, le16(elf, 60));
    let segment = |i: usize| {
        let ph = phoff + 56 * i;
        (le64(elf, ph + 8) as usize, le64(elf, ph + 32) as usize)
    };
    let section = |i: usize| {
        let sh = shoff + 64 * i;
        (
            le32(elf, sh + 4),
            le64(elf, sh + 24) as usize,
            le64(elf, sh + 32) as usize,
            le32(elf, sh + 40),
        )
    };
    let symtab = (0..shnum)
        .find(|&i| section(i).0 == 2)
        .expect("a symbol table");
    let (_, sym_off, sym_size, link) = section(symtab);
    let (_, str_off, str_size, _) = section(link as usize);
    let symbols = [&b"__stack_top\0"[..], b"__advice_top\0"].map(|name| {
        (0..sym_size / 24)
            .map(|s| sym_off + 24 * s)
            .find(|&sym| elf[str_off + le32(elf, sym) as usize..].starts_with(name))
            .expect("the linker script's symbols")
    });
    ElfLayout {
        phoff,
        phnum,
        shoff,
        shnum,
        text: segment(0),
        data: segment(1),
        symtab: (sym_off, sym_size),
        strtab: (str_off, str_size),
        symbols,
    }
}

/// Instruction words covering every opcode, and for the opcodes rv64im and the hash precompile
/// use every `funct3` and the `funct7` values the decoder tells apart, with varied registers and
/// immediates: what the digest of a text holding them pins is the decoder.
fn instruction_words() -> Vec<u32> {
    const DECODED: [u32; 14] = [
        0x03, 0x0b, 0x0f, 0x13, 0x17, 0x1b, 0x23, 0x33, 0x37, 0x3b, 0x63, 0x67, 0x6f, 0x73,
    ];
    let mut words = Vec::new();
    let mut seed = 0x9e37_79b9_u32;
    let mut word = |opcode: u32, f3: u32, f7: u32| {
        seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let regs = seed >> 17;
        let (rd, rs1, rs2) = (regs & 31, (regs >> 5) & 31, (regs >> 10) & 31);
        // Every other word keeps x0 as its destination, which ECALL, FENCE and the hash
        // precompile need.
        let rd = if seed & 1 == 0 { 0 } else { rd };
        opcode | rd << 7 | f3 << 12 | rs1 << 15 | rs2 << 20 | f7 << 25
    };
    for opcode in 0..128u32 {
        if DECODED.contains(&opcode) {
            for f3 in 0..8u32 {
                for f7 in [0x00u32, 0x01, 0x02, 0x20, 0x21, 0x7f] {
                    words.push(word(opcode, f3, f7));
                }
            }
        } else {
            words.push(word(opcode, opcode % 8, opcode));
        }
    }
    words.extend([
        0x73,
        0x0010_0073,
        0x0000_000b,
        0x0000_100b,
        0x0000_200b,
        0x0000_008b,
        0x0000_100f,
    ]);
    words
}

/// Add overlapping symbol-table views before the original sections. All inserted
/// symbols have empty names, so the guest and its proof retain their meaning.
fn overlapping_symbol_tables(elf: &[u8]) -> Vec<Edit> {
    let n = 512usize;
    let old_offset = le64(elf, 40) as usize;
    let old_count = le16(elf, 60);
    let symbol_offset = elf.len();
    let string_offset = symbol_offset + 24 * n;
    let header_offset = string_offset + 32;
    let mut file = elf.to_vec();
    file.resize(header_offset + 64 * (n + old_count + 1), 0);
    for i in 0..n {
        let h = header_offset + 64 * i;
        file[h + 4..h + 8].copy_from_slice(&2u32.to_le_bytes());
        file[h + 24..h + 32].copy_from_slice(&((symbol_offset + 24 * i) as u64).to_le_bytes());
        file[h + 32..h + 40].copy_from_slice(&((24 * (n - i)) as u64).to_le_bytes());
        file[h + 40..h + 44].copy_from_slice(&((n + old_count) as u32).to_le_bytes());
        file[h + 56..h + 64].copy_from_slice(&24u64.to_le_bytes());
    }
    for i in 0..old_count {
        let h = header_offset + 64 * (n + i);
        file[h..h + 64].copy_from_slice(&elf[old_offset + 64 * i..old_offset + 64 * (i + 1)]);
        if le32(&file, h + 4) == 2 {
            let link = le32(&file, h + 40) as u32 + n as u32;
            file[h + 40..h + 44].copy_from_slice(&link.to_le_bytes());
        }
    }
    let h = header_offset + 64 * (n + old_count);
    file[h + 4..h + 8].copy_from_slice(&3u32.to_le_bytes());
    file[h + 24..h + 32].copy_from_slice(&(string_offset as u64).to_le_bytes());
    file[h + 32..h + 40].copy_from_slice(&32u64.to_le_bytes());
    vec![
        set64(elf, 40, header_offset as u64),
        Edit::Splice(60, 2, ((n + old_count + 1) as u16).to_le_bytes().to_vec()),
        Edit::Splice(elf.len(), 0, file[elf.len()..].to_vec()),
    ]
}

/// What the ELF edits make of each guest: its digest, or `null` when it is no guest.
fn program_cases(out: &mut Vec<String>) {
    for (n, name) in ELFS.into_iter().enumerate() {
        let elf = read(name);
        let l = elf_layout(&elf);
        let full = n == 0;
        let mut cases: Vec<Vec<Edit>> = vec![vec![]];
        if full {
            let edits = overlapping_symbol_tables(&elf);
            assert_eq!(
                leanvm_reference::program_digest(&edited(&elf, &edits)).unwrap(),
                leanvm_reference::program_digest(&elf).unwrap()
            );
            cases.push(edits);
        }
        // The ELF header.
        for at in 0..64 {
            cases.push(xor(at, 0x01));
            if full {
                cases.push(xor(at, 0x80));
            }
        }
        // The program headers: every byte of the loaded segments', and the others' types.
        for i in 0..l.phnum {
            let ph = l.phoff + 56 * i;
            let bytes = if i < 3 && full { 0..56 } else { 0..4 };
            for at in bytes {
                cases.push(xor(ph + at, 0x01));
            }
        }
        for (i, kind) in [(3, 2u32), (3, 3), (4, 7), (2, 1)] {
            cases.push(vec![set32(&elf, l.phoff + 56 * i, kind)]);
        }
        // Segment flags: a writable text, executable data.
        cases.push(vec![set32(&elf, l.phoff + 4, 7)]);
        cases.push(vec![set32(&elf, l.phoff + 56 + 4, 7)]);
        cases.push(vec![set32(&elf, l.phoff + 56 + 4, 5)]);
        // Segment shapes: the field at `field` of program header `i` set to `value`.
        let ph = |i: usize, field: usize, value: u64| set64(&elf, l.phoff + 56 * i + field, value);
        let (text_vaddr, text_filesz) = (le64(&elf, l.phoff + 16), l.text.1 as u64);
        let (data_vaddr, data_filesz) = (le64(&elf, l.phoff + 56 + 16), l.data.1 as u64);
        let entry = le64(&elf, 24);
        for edits in [
            // Sizes that are no whole word: the last word is zero-padded.
            vec![ph(0, 32, text_filesz - 2)],
            vec![ph(1, 32, data_filesz - 1)],
            vec![ph(1, 32, data_filesz - 1), ph(1, 40, data_filesz - 1)],
            // More memory than file: no more text, and RAM's data ending later.
            vec![ph(0, 40, text_filesz + 0x1000)],
            vec![ph(1, 40, data_filesz + 0x1000)],
            vec![ph(1, 40, 1 << 40)],
            // The text starting a page later, with the entry moved along or not.
            vec![
                ph(0, 16, text_vaddr + 0x1000),
                set64(&elf, 24, entry + 0x1000),
            ],
            vec![ph(0, 16, text_vaddr + 0x1000)],
            // Overlapping segments, and an empty one.
            vec![ph(2, 16, data_vaddr + 8)],
            vec![ph(1, 16, text_vaddr), ph(1, 40, 8)],
            vec![ph(2, 40, 0)],
            vec![ph(2, 32, 0), ph(2, 40, 0), ph(2, 16, 0)],
            // Alignment: none, one, not a power of two, inconsistent with the offset.
            vec![ph(0, 48, 0)],
            vec![ph(0, 48, 1)],
            vec![ph(0, 48, 3)],
            vec![ph(0, 48, 8), ph(0, 8, l.text.0 as u64 + 4)],
            // A second text segment, inside and outside the text region.
            vec![
                set32(&elf, l.phoff + 56 * 3, 1),
                set32(&elf, l.phoff + 56 * 3 + 4, 5),
            ],
            vec![
                set32(&elf, l.phoff + 56 * 3, 1),
                set32(&elf, l.phoff + 56 * 3 + 4, 5),
                ph(3, 16, text_vaddr + 0x2000),
                ph(3, 24, text_vaddr + 0x2000),
            ],
            // No program headers, and headers past the end of the file.
            vec![Edit::Xor(56, (l.phnum as u16).to_le_bytes().to_vec())],
            vec![set64(&elf, 32, elf.len() as u64 - 100)],
            vec![set64(&elf, 32, u64::MAX - 8)],
            vec![set64(&elf, 40, u64::MAX - 8)],
        ] {
            cases.push(edits);
        }
        // The section headers: every type, and every byte of the symbol and string tables'.
        for i in 0..l.shnum {
            let sh = l.shoff + 64 * i;
            for at in 4..8 {
                cases.push(xor(sh + at, 0x01));
            }
            let (kind, offset) = (le32(&elf, sh + 4), le64(&elf, sh + 24) as usize);
            if full && (kind == 2 || (kind == 3 && offset == l.strtab.0)) {
                for at in (0..64).filter(|at| !(4..8).contains(at)) {
                    cases.push(xor(sh + at, 0x01));
                }
            }
        }
        // The two symbols the loader reads, and their names.
        for &sym in &l.symbols {
            for at in 0..24 {
                cases.push(xor(sym + at, 0x01));
            }
            let name = l.strtab.0 + le32(&elf, sym) as usize;
            for at in 0..12 {
                cases.push(xor(name + at, 0x01));
            }
        }
        // RAM and the advice of other sizes: powers of two and not.
        let stack_top = l.symbols[0] + 8;
        let ram = 0x4000_0000u64;
        for top in [
            ram + (1 << 12),
            ram + (1 << 30),
            ram + (1 << 31),
            ram + 8,
            ram + 24,
            ram,
            ram - 8,
            u64::MAX,
        ] {
            cases.push(vec![set64(&elf, stack_top, top)]);
        }
        let advice_top = l.symbols[1] + 8;
        let advice = 0x2000_0000u64;
        for top in [
            advice + 8,
            advice + (1 << 29),
            advice + (1 << 30),
            advice + 16 + 8,
            advice,
        ] {
            cases.push(vec![set64(&elf, advice_top, top)]);
        }
        // The entry point: the next instruction, unaligned, outside the text.
        let entry = le64(&elf, 24);
        for e in [
            entry + 4,
            entry + 2,
            entry - 4,
            entry + l.text.1 as u64,
            entry + l.text.1 as u64 - 4,
        ] {
            cases.push(vec![set64(&elf, 24, e)]);
        }
        // The text and the data.
        for at in (l.text.0..l.text.0 + l.text.1).step_by(if full { 97 } else { 401 }) {
            cases.push(xor(at, 1 << (at % 8)));
        }
        for at in (l.data.0..l.data.0 + l.data.1).step_by(13) {
            cases.push(xor(at, 0x01));
        }
        // A sample of everything else.
        for at in (0..elf.len()).step_by(if full { 127 } else { 251 }) {
            cases.push(xor(at, 0x10));
        }
        let _ = l.symtab;
        // Truncations and extensions.
        let mut lengths = vec![
            0,
            1,
            7,
            63,
            64,
            100,
            l.phoff + 56 * l.phnum - 1,
            l.text.0 + 3,
            elf.len() - 1,
        ];
        lengths.extend((512..elf.len()).step_by(if full { 512 } else { 2048 }));
        for len in lengths {
            cases.push(vec![Edit::Truncate(len)]);
        }
        cases.push(vec![Edit::Splice(elf.len(), 0, vec![0])]);
        cases.push(vec![Edit::Splice(elf.len(), 0, vec![0xff; 8])]);
        // Texts holding every kind of instruction word.
        if full {
            let words = instruction_words();
            let per = l.text.1 / 4;
            for chunk in words.chunks(per) {
                let bytes: Vec<u8> = chunk.iter().flat_map(|w| w.to_le_bytes()).collect();
                let old = &elf[l.text.0..l.text.0 + bytes.len()];
                let diff = bytes.iter().zip(old).map(|(a, b)| a ^ b).collect();
                cases.push(vec![Edit::Xor(l.text.0, diff)]);
            }
        }
        for edits in cases {
            let file = edited(&elf, &edits);
            let digest = leanvm_reference::program_digest(&file)
                .map_or_else(|_| String::from("null"), |d| format!("\"0x{}\"", hex(&d)));
            out.push(format!(
                "{{\"elf\":\"{name}\",\"edits\":{},\"digest\":{digest}}}",
                edits_json(&edits)
            ));
        }
    }
}

/// Where the parts of a proof sit: its scalar stream and each Merkle phase's rows and siblings.
struct ProofLayout {
    stream: usize,
    scalars: usize,
    phases_at: usize,
    phases: Vec<Phase>,
}

struct Phase {
    at: usize,
    rows: Vec<(usize, usize)>,
    siblings_at: usize,
    siblings: usize,
    end: usize,
}

fn proof_layout(proof: &[u8]) -> ProofLayout {
    let mut at = 6;
    let scalars = le64(proof, at) as usize;
    let stream = at + 8;
    at = stream + 24 * scalars;
    let phases_at = at;
    let n = le64(proof, at) as usize;
    at += 8;
    let mut phases = Vec::new();
    for _ in 0..n {
        let start = at;
        let rows = le64(proof, at) as usize;
        at += 8;
        let mut row_spans = Vec::new();
        for _ in 0..rows {
            let words = le64(proof, at) as usize;
            row_spans.push((at, words));
            at += 8 + 8 * words;
        }
        let siblings_at = at;
        let siblings = le64(proof, at) as usize;
        at += 8 + 32 * siblings;
        phases.push(Phase {
            at: start,
            rows: row_spans,
            siblings_at,
            siblings,
            end: at,
        });
    }
    assert_eq!(at, proof.len(), "the proof parses");
    ProofLayout {
        stream,
        scalars,
        phases_at,
        phases,
    }
}

/// Adds `delta` to the length prefix at `at`.
fn bump(proof: &[u8], at: usize, delta: i64) -> Edit {
    set64(proof, at, le64(proof, at).wrapping_add_signed(delta))
}

/// One proof case: what the edits of a fixture proof, verified against a guest and an output,
/// come to.
struct ProofCase {
    elf: Option<(&'static str, Vec<Edit>)>,
    edits: Vec<Edit>,
    output: Option<[u8; 32]>,
}

impl ProofCase {
    const fn proof(edits: Vec<Edit>) -> Self {
        Self {
            elf: None,
            edits,
            output: None,
        }
    }
}

fn proof_mutations(proof: &[u8], full: bool) -> Vec<ProofCase> {
    let l = proof_layout(proof);
    let mut cases = vec![ProofCase::proof(vec![])];
    let mut add = |edits: Vec<Edit>| cases.push(ProofCase::proof(edits));
    // The header and the stream's length.
    for at in 0..14 {
        add(xor(at, 0x01));
    }
    add(vec![set64(proof, 4, 2)]);
    add(xor(4, 0x02));
    for at in [7, 10, 13] {
        add(xor(at, 0x80));
    }
    // The announcement (table heights, rate, final clock), the root and what follows: every limb.
    let scalar = |i: usize, limb: usize| l.stream + 24 * i + 8 * limb;
    let head = if full { 48 } else { 14 };
    for i in 0..head.min(l.scalars) {
        for limb in 0..3 {
            add(xor(scalar(i, limb), 0x01));
        }
    }
    // Announced values out of range.
    for (i, value) in [
        (0, 0u64),
        (0, 2),
        (0, 33),
        (0, 1 << 32),
        (7, 3),
        (6, 40),
        (8, 0),
        (8, 2),
        (8, 5),
        (9, 0),
    ] {
        add(vec![set64(proof, scalar(i, 0), value)]);
    }
    add(vec![set64(proof, scalar(9, 1), 1)]);
    add(vec![set64(proof, scalar(10, 2), 1)]);
    add(vec![set64(proof, scalar(11, 2), 1)]);
    // A sample of the stream, and its tail.
    let stride = if full { 23 } else { 151 };
    for i in (head..l.scalars).step_by(stride) {
        let at = scalar(i, i % 3) + i % 8;
        add(xor(at, 1 << (i % 8)));
    }
    for i in l.scalars.saturating_sub(if full { 8 } else { 2 })..l.scalars {
        add(xor(scalar(i, 0), 0x01));
    }
    // A scalar more or less: the stream is no longer fully read, or runs out.
    add(vec![
        bump(proof, 6, 1),
        Edit::Splice(l.phases_at, 0, vec![0; 24]),
    ]);
    add(vec![
        bump(proof, 6, -1),
        Edit::Splice(l.phases_at - 24, 24, vec![]),
    ]);
    // The Merkle phases.
    add(xor(l.phases_at, 0x01));
    add(xor(l.phases_at + 7, 0x80));
    for (n, phase) in l.phases.iter().enumerate() {
        if !full && n > 0 && n + 1 < l.phases.len() {
            continue;
        }
        add(xor(phase.at, 0x01));
        add(xor(phase.at + 7, 0x80));
        let rows = phase.rows.len();
        for &r in &[0, rows / 2, rows - 1] {
            let (row_at, words) = phase.rows[r];
            add(xor(row_at, 0x01));
            add(xor(row_at + 8, 0x01));
            add(xor(row_at + 8 + 8 * (words - 1) + 7, 0x80));
            if full {
                add(xor(row_at + 8 + 8 * (words / 2) + 3, 0x10));
            }
        }
        add(xor(phase.siblings_at, 0x01));
        for s in [0, phase.siblings / 2, phase.siblings - 1] {
            add(xor(phase.siblings_at + 8 + 32 * s + s % 32, 0x01));
        }
        // A sibling more, one fewer.
        add(vec![
            bump(proof, phase.siblings_at, 1),
            Edit::Splice(phase.end, 0, vec![0; 32]),
        ]);
        add(vec![
            bump(proof, phase.siblings_at, -1),
            Edit::Splice(phase.end - 32, 32, vec![]),
        ]);
        // A wider row, one row fewer, one row more.
        let (row_at, words) = phase.rows[0];
        add(vec![
            bump(proof, row_at, 1),
            Edit::Splice(row_at + 8, 0, vec![0; 8]),
        ]);
        add(vec![
            bump(proof, row_at, -1),
            Edit::Splice(row_at + 8, 8, vec![]),
        ]);
        let last = phase.rows[rows - 1];
        let last_end = last.0 + 8 + 8 * last.1;
        add(vec![
            bump(proof, phase.at, -1),
            Edit::Splice(last.0, last_end - last.0, vec![]),
        ]);
        let copy = proof[row_at..row_at + 8 + 8 * words].to_vec();
        add(vec![
            bump(proof, phase.at, 1),
            Edit::Splice(phase.siblings_at, 0, copy),
        ]);
    }
    // A phase more, one fewer.
    add(vec![
        bump(proof, l.phases_at, 1),
        Edit::Splice(proof.len(), 0, vec![0; 16]),
    ]);
    let last = l.phases.last().unwrap();
    add(vec![bump(proof, l.phases_at, -1), Edit::Truncate(last.at)]);
    // Truncations and extensions.
    let mut lengths = vec![
        0,
        3,
        4,
        5,
        6,
        13,
        14,
        l.stream + 24,
        l.phases_at,
        l.phases_at + 8,
    ];
    lengths.extend(l.phases.iter().map(|p| p.end - 1));
    lengths.extend([proof.len() - 32, proof.len() - 8, proof.len() - 1]);
    if full {
        lengths.extend((1000..proof.len()).step_by(9973));
    }
    for len in lengths {
        add(vec![Edit::Truncate(len)]);
    }
    add(vec![Edit::Splice(proof.len(), 0, vec![0])]);
    add(vec![Edit::Splice(proof.len(), 0, vec![0; 8])]);
    add(vec![Edit::Splice(
        proof.len(),
        0,
        proof[proof.len() - 32..].to_vec(),
    )]);
    cases
}

/// Statement edits: other outputs, and other guests, some with the same digest.
fn statement_mutations(
    name: &'static str,
    elf: &[u8],
    output: [u8; 32],
    full: bool,
) -> Vec<ProofCase> {
    let mut cases = Vec::new();
    let positions: Vec<usize> = if full {
        (0..32).collect()
    } else {
        vec![0, 8, 31]
    };
    for at in positions {
        let mut o = output;
        o[at] ^= 0x01;
        cases.push(ProofCase {
            elf: None,
            edits: vec![],
            output: Some(o),
        });
    }
    cases.push(ProofCase {
        elf: None,
        edits: vec![],
        output: Some([0; 32]),
    });
    let other = ELFS.into_iter().find(|&e| e != name).unwrap();
    cases.push(ProofCase {
        elf: Some((other, vec![])),
        edits: vec![],
        output: None,
    });
    if full {
        cases.push(ProofCase {
            elf: Some((name, overlapping_symbol_tables(elf))),
            edits: vec![],
            output: None,
        });
    }
    let l = elf_layout(elf);
    let elf_edits = [
        // The same program: trailing bytes, an unused symbol's name, a section's flags.
        vec![Edit::Splice(elf.len(), 0, vec![0; 8])],
        xor(l.strtab.0 + 1, 0x01),
        xor(l.shoff + 64 + 8, 0x01),
        // Another program: an instruction, an image byte, RAM's size, the entry.
        xor(l.text.0 + 8, 0x01),
        xor(l.data.0, 0x01),
        vec![set64(
            elf,
            l.symbols[0] + 8,
            le64(elf, l.symbols[0] + 8) * 2 - 0x4000_0000,
        )],
        vec![set64(elf, 24, le64(elf, 24) + 4)],
        // No guest.
        vec![Edit::Truncate(63)],
    ];
    for edits in elf_edits {
        cases.push(ProofCase {
            elf: Some((name, edits)),
            edits: vec![],
            output: None,
        });
    }
    cases
}

fn proof_cases(out: &mut Vec<String>) {
    for (n, (elf_name, fixture)) in PROOFS.into_iter().enumerate() {
        let full = n == 0;
        let elf = read(elf_name);
        let proof = read(&format!("{fixture}.proof"));
        let output: [u8; 32] = read(&format!("{fixture}.output"))
            .try_into()
            .expect("a 32-byte output");
        let mut cases = proof_mutations(&proof, full);
        cases.extend(statement_mutations(elf_name, &elf, output, full));
        for case in cases {
            let (guest, elf_edits) = case.elf.clone().unwrap_or((elf_name, vec![]));
            let guest_bytes = edited(&read(guest), &elf_edits);
            let proof_bytes = edited(&proof, &case.edits);
            let o = case.output.unwrap_or(output);
            let ok = leanvm_reference::verify(&guest_bytes, o, &proof_bytes).is_ok();
            let mut line = format!(
                "{{\"proof\":\"{fixture}\",\"edits\":{}",
                edits_json(&case.edits)
            );
            if let Some((guest, edits)) = &case.elf {
                let _ = write!(
                    line,
                    ",\"elf\":\"{guest}\",\"elfEdits\":{}",
                    edits_json(edits)
                );
            }
            if let Some(o) = case.output {
                let _ = write!(line, ",\"output\":\"0x{}\"", hex(&o));
            }
            let _ = write!(line, ",\"ok\":{ok}}}");
            out.push(line);
        }
    }
}

/// The vectors file's contents.
pub(crate) fn vectors() -> String {
    let fixtures: Vec<String> = PROOFS
        .iter()
        .map(|(elf, fixture)| format!("{{\"elf\":\"{elf}\",\"proof\":\"{fixture}\"}}"))
        .collect();
    let mut programs = Vec::new();
    program_cases(&mut programs);
    let mut proofs = Vec::new();
    proof_cases(&mut proofs);
    format!(
        "{{\n\"fixtures\":[\n{}\n],\n\"programs\":[\n{}\n],\n\"proofs\":[\n{}\n]\n}}\n",
        fixtures.join(",\n"),
        programs.join(",\n"),
        proofs.join(",\n")
    )
}
