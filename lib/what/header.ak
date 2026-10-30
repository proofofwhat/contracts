//// Parsing and proof-of-work checking for an 80-byte Bitcoin header.
////
//// WHAT headers are byte-for-byte in Bitcoin's format so that unmodified
//// SHA-256d hardware can mine them (whitepaper section 4):
////
//// | offset | bytes | field       |
//// |--------|-------|-------------|
//// |      0 |     4 | version     |
//// |      4 |    32 | prev_hash   |
//// |     36 |    32 | merkle_root |
//// |     68 |     4 | time        |
//// |     72 |     4 | bits        |
//// |     76 |     4 | nonce       |

use aiken/crypto.{sha2_256}
use aiken/math.{pow2}
use aiken/primitive/bytearray

pub const header_length = 80

/// Fields the validator actually uses. `version`, `time` and `nonce` are free
/// search space for the miner and are deliberately not constrained.
pub type Header {
  prev_hash: ByteArray,
  merkle_root: ByteArray,
  /// Target the miner committed to, decoded from nBits.
  target: Int,
}

/// SHA-256d of the header, in Bitcoin's internal byte order.
pub fn hash(header: ByteArray) -> ByteArray {
  header |> sha2_256 |> sha2_256
}

/// Parse the fields the protocol constrains. Fails on a header of the wrong
/// length or with an nBits field that is negative, zero, or overflowing.
pub fn parse(header: ByteArray) -> Header {
  expect bytearray.length(header) == header_length

  Header {
    prev_hash: bytearray.slice(header, 4, 35),
    merkle_root: bytearray.slice(header, 36, 67),
    target: decode_bits(bytearray.slice(header, 72, 75)),
  }
}

/// Decode Bitcoin's 4-byte compact target ("nBits") into a full target.
///
/// The field is a little-endian 32-bit word 0xEEMMMMMM: a one-byte exponent
/// and a 24-bit mantissa, meaning `mantissa * 256^(exponent - 3)`.
pub fn decode_bits(bits: ByteArray) -> Int {
  expect bytearray.length(bits) == 4

  let compact = bytearray.to_int_little_endian(bits)
  let exponent = compact / 16777216
  let mantissa = compact % 16777216

  // As in Bitcoin, the top mantissa bit is a sign bit and a negative target is
  // nonsense. A zero mantissa would make every hash a winner, and an exponent
  // past 32 would push the target beyond 256 bits.
  expect mantissa > 0
  expect mantissa < 8388608
  expect exponent >= 3
  expect exponent <= 32

  mantissa * pow2(8 * ( exponent - 3 ))
}

/// Did this header meet the target it committed to?
///
/// Bitcoin reads the hash as a little-endian 256-bit number, so the leading
/// zero bytes a miner searches for sit at the end of the byte string.
pub fn meets_target(header_hash: ByteArray, target: Int) -> Bool {
  bytearray.to_int_little_endian(header_hash) <= target
}

// Bitcoin block 100,000, verbatim, as the fixture for every parsing test.
const block_100k =
  #"0100000050120119172a610421a6c3011dd330d9df07b63616c2cc1f1cd00200000000006657a9252aacd5c0b2940996ecff952228c3067cc38d4885efb5a4ac4247e9f337221b4d4c86041b0f2b5710"

test parses_block_100k() {
  let h = parse(block_100k)

  and {
    h.prev_hash == #"50120119172a610421a6c3011dd330d9df07b63616c2cc1f1cd0020000000000",
    h.merkle_root == #"6657a9252aacd5c0b2940996ecff952228c3067cc38d4885efb5a4ac4247e9f3",
    // 0x1b04864c
    h.target == 0x4864c000000000000000000000000000000000000000000000000,
  }
}

test hashes_block_100k() {
  // Displayed as 000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506
  hash(block_100k) == #"06e533fd1ada86391f3f6c343204b0d278d4aaec1c0b20aa27ba030000000000"
}

test block_100k_meets_its_target() {
  let h = parse(block_100k)

  meets_target(hash(block_100k), h.target)
}

test rejects_short_header() fail {
  parse(bytearray.take(block_100k, 79)) == parse(block_100k)
}

test decodes_min_difficulty_bits() {
  // 0x1d00ffff, Bitcoin's pow limit, little-endian in the header.
  decode_bits(#"ffff001d") == 0xffff0000000000000000000000000000000000000000000000000000
}

test rejects_zero_bits() fail {
  decode_bits(#"00000003") > 0
}

test rejects_negative_bits() fail {
  // Sign bit set in the mantissa.
  decode_bits(#"ffffff1d") > 0
}
