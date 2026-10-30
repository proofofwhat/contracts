//// The coinbase commitment: the only payload a WHAT block carries.
////
//// Whitepaper section 4. A short byte string whose SHA-256d is the header's
//// merkle root, so the payout address, and the datum the payout carries, are
//// inside the work. A solution copied out of the Cardano mempool still pays its
//// original finder, under the datum the finder chose, which is what makes
//// front-running pointless.
////
//// | offset   | bytes | field                                              |
//// |----------|-------|----------------------------------------------------|
//// |        0 |     4 | chain tag, "WHAT"                                  |
//// |        4 |     4 | block height, big-endian                           |
//// |        8 |     2 | address length N, big-endian                       |
//// |       10 |     N | payout address, CBOR-serialised                    |
//// |   10 + N |    32 | `datum_hash` of the payout output's datum field    |
//// |   42 + N |    .. | miner extranonce space                             |
////
//// There is no room in this format for an auxiliary proof-of-work structure,
//// so a WHAT hash cannot also count toward a Bitcoin block. That exclusivity
//// is what makes WHAT's hashrate a measurement rather than a byproduct.

use aiken/builtin
use aiken/crypto.{blake2b_256, sha2_256}
use aiken/primitive/bytearray
use cardano/transaction.{Datum, DatumHash, InlineDatum, NoDatum}
use what/parameters.{chain_tag, max_address_length, max_coinbase_length}

pub type Coinbase {
  height: Int,
  /// `builtin.serialise_data` of the payout `Address`. Compared against the
  /// payout output's address rather than decoded, so any address shape the
  /// ledger accepts -- key or script, with or without a stake part -- works
  /// without the validator knowing anything about address encoding.
  address: ByteArray,
  /// `datum_hash` of the datum field the payout output must carry.
  datum: ByteArray,
}

/// With an empty merkle branch, Bitcoin's merkle root is just the double hash
/// of the single coinbase.
pub fn merkle_root(coinbase: ByteArray) -> ByteArray {
  coinbase |> sha2_256 |> sha2_256
}

/// What the coinbase commits for an output's datum: the hash of the whole
/// field, as the ledger hands it to a script -- `NoDatum`, `DatumHash(h)` or
/// `InlineDatum(d)`.
///
/// Hashing the field rather than the datum keeps the commitment 32 bytes
/// whatever the datum is, and lets "no datum" be a commitment like any other.
/// A wallet commits `NoDatum`; a script that needs datum `d` commits
/// `InlineDatum(d)`; a Plutus V1 script, which cannot spend inline datums,
/// commits `DatumHash(h)`.
///
/// The bytes hashed are `serialise_data`'s, not the bytes the datum was
/// submitted in. The off-chain side must hash the same canonical encoding.
pub fn datum_hash(datum: Datum) -> ByteArray {
  blake2b_256(builtin.serialise_data(datum))
}

/// Parse a commitment, failing on anything malformed or oversized.
pub fn parse(coinbase: ByteArray) -> Coinbase {
  let length = bytearray.length(coinbase)

  expect length >= 10
  expect length <= max_coinbase_length
  expect bytearray.take(coinbase, 4) == chain_tag

  let address_length = bytearray.to_int_big_endian(
    bytearray.slice(coinbase, 8, 9),
  )

  expect address_length > 0
  expect address_length <= max_address_length
  expect length >= 42 + address_length

  Coinbase {
    height: bytearray.to_int_big_endian(bytearray.slice(coinbase, 4, 7)),
    address: bytearray.slice(coinbase, 10, 9 + address_length),
    datum: bytearray.slice(coinbase, 10 + address_length, 41 + address_length),
  }
}

const some_datum =
  #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

const example =
  #"574841540000002a0004deadbeefaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00112233445566778899"

test parses_a_commitment() {
  parse(example) == Coinbase {
    height: 42,
    address: #"deadbeef",
    datum: some_datum,
  }
}

test extranonce_does_not_disturb_the_fields() {
  let a = parse(example)
  let b = parse(bytearray.concat(example, #"ffffffffffffffff"))

  a == b
}

test the_extranonce_may_be_empty() {
  parse(
    #"574841540000002a0004deadbeefaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  ).datum == some_datum
}

test rejects_a_foreign_chain_tag() fail {
  parse(
    #"54554e410000002a0004deadbeefaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  ).height == 42
}

test rejects_a_truncated_address() fail {
  parse(#"574841540000002a0004dead").height == 42
}

test rejects_an_empty_address() fail {
  parse(
    #"574841540000002a0000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  ).height == 42
}

test rejects_a_missing_datum_commitment() fail {
  // The old format: an address and nothing after it.
  parse(#"574841540000002a0004deadbeef").height == 42
}

test rejects_a_truncated_datum_commitment() fail {
  // 31 bytes where 32 are needed.
  parse(
    #"574841540000002a0004deadbeefaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  ).height == 42
}

// The datum commitment is the second permanent encoding after the address:
// the off-chain node computes these bytes on its own, and its own tests assert
// the same literals.

test no_datum_serialises_as_constructor_zero() {
  builtin.serialise_data(NoDatum) == #"d87980"
}

test the_no_datum_commitment_is_pinned() {
  datum_hash(NoDatum) == #"923918e403bf43c34b4ef6b48eb2ee04babed17320d8d1b9ff9ad086e86f44ec"
}

test an_inline_datum_commitment_is_pinned() {
  and {
    builtin.serialise_data(InlineDatum(builtin.i_data(42))) == #"d87b9f182aff",
    datum_hash(InlineDatum(builtin.i_data(42))) == blake2b_256(#"d87b9f182aff"),
  }
}

test a_datum_hash_commitment_is_pinned() {
  builtin.serialise_data(DatumHash(some_datum)) == #"d87a9f5820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaff"
}

test the_three_datum_shapes_commit_differently() {
  let none = datum_hash(NoDatum)
  let hashed = datum_hash(DatumHash(blake2b_256(#"d87980")))
  let inline = datum_hash(InlineDatum(builtin.constr_data(0, [])))

  and {
    none != hashed,
    none != inline,
    hashed != inline,
  }
}
