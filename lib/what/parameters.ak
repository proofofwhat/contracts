//// Protocol constants for Proof of What? (WHAT).
////
//// Anything in here is baked into the script hash, which is also the WHAT
//// minting policy id. Changing any value here changes the chain's identity.

use aiken/math.{pow2}

/// Token name of the WHAT native asset, minted one block reward at a time.
pub const token_name = "WHAT"

/// Token name of the state-thread NFT that identifies the tip UTxO.
pub const tip_token_name = "tip"

/// Magic prefix of the coinbase commitment. Also the chain tag.
pub const chain_tag = "WHAT"

/// Bitcoin's issuance schedule, unchanged: 50 WHAT, halving every 210,000
/// blocks, 8 decimals. The cap is 20,999,949.9769 WHAT -- fifty below
/// Bitcoin's, because the genesis header at height 0 mints nothing.
pub const halving_number = 210_000

pub const initial_payout = 5_000_000_000

/// Target block interval, in milliseconds. Cardano's POSIX times are in ms.
pub const target_spacing = 600_000

/// Half-life, in milliseconds: how long an overdue block takes to double the
/// allowed target, and the gain of the per-block update. Whitepaper section 6.
/// A sweep of 5 minutes to 1 hour favours the short end -- the
/// mean holds throughout while the interval tail tightens as this falls -- so
/// 10 minutes, equal to the target spacing, is the working value.
pub const half_life = 600_000

/// Easiest target the protocol will ever allow: `0x7fffff * 256^29`, which is
/// about two hashes a block. That is a full-width nBits mantissa at the
/// loosest exponent that still fits a 256-bit target. nBits can encode one
/// step more with a narrower mantissa -- `0xffff * 256^30`, exactly twice as
/// loose, one hash a block -- which is not worth the special case.
///
/// Deliberately not Bitcoin's 2^224. Bitcoin stops loosening at difficulty 1
/// because it has to -- a chain with no other clock cannot let blocks become
/// free. WHAT takes its time from Cardano and pays per block from a
/// height-indexed schedule, so the rate is governed by the decay law and the
/// per-block tightening, not by the cost of a hash: a lone CPU mints at ~600 s
/// whatever the target, and the moment it stops being lone the target tightens
/// under it. Clamping at 2^224 does not prevent cheap blocks, it only makes
/// issuance fall behind 600 s whenever the hashpower present is below
/// Bitcoin's floor -- which is the one case this chain exists to serve.
///
/// So the only ceiling left is the header format's. If nobody is hashing, the
/// first hash that shows up should win.
pub fn pow_limit() -> Int {
  ( pow2(23) - 1 ) * pow2(232)
}

/// A reference value for the validator's `initial_target` parameter: the base
/// target a single ~1 TH/s rig takes about five minutes a block at (2^48
/// expected hashes, difficulty 65,535). 2^207 is the ten-minute figure for the
/// same rig. Not used by the validator — T0 is a parameter, chosen per chain —
/// but kept here as a starting point to reason from.
pub fn reference_initial_target() -> Int {
  pow2(208)
}

/// Beyond this many half-lives either side of schedule the exponential is
/// clamped instead of evaluated. Every target is below 2^255 and the base is at
/// least 1, so from 255 shifts up the law lands on the pow limit anyway: the
/// cutoff never changes a result, it only skips the arithmetic. At 64 it did
/// change one -- a base tighter than about 2^191 jumped straight to the pow
/// limit after a long stall, and the catch-up ran ahead of schedule. The
/// price is integers of about 530 bits on that path.
pub const max_shift = 256

/// Longest coinbase commitment the validator will parse, in bytes.
pub const max_coinbase_length = 256

/// Longest serialised Cardano address the coinbase may commit to, in bytes.
pub const max_address_length = 128

/// Widest transaction validity interval accepted, in milliseconds. Bounds how
/// stale the timestamp a block records can be. Whitepaper sections 5 and 6:
/// two minutes.
pub const max_validity_span = 120_000
