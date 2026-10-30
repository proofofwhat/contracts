use cardano/transaction.{OutputReference}

/// The tip of the WHAT chain, held in the datum of the single UTxO that
/// carries the state-thread token.
///
/// This is the whole of the chain's difficulty state. The rule is relative to
/// the last block, so `base_target` and `current_time` together determine the
/// target every miner is working against at any instant (whitepaper section
/// 6); nothing is accumulated and there is no anchor.
pub type State {
  /// Height of the tip block. Genesis is 0.
  block_number: Int,
  /// SHA-256d of the tip header, in Bitcoin's internal byte order, which is
  /// exactly what the next header's prev_hash field must contain.
  current_hash: ByteArray,
  /// Validity-interval start of the transaction that submitted the tip block,
  /// in POSIX milliseconds. Cardano's attestation of when this block landed,
  /// and the reference the next block's interval is measured from.
  current_time: Int,
  /// T: the base target, before any in-flight loosening.
  base_target: Int,
}

/// The only thing that sits at the script address under a datum the
/// validator recognises.
///
/// Rewards are paid to the address the work commits to, never here, so there
/// is no second kind of datum to dispatch on. Anything else at this address --
/// a mistaken send, a published reference script -- matches nothing and can
/// never be spent.
pub type WhatDatum {
  Tip { state: State }
}

/// Redeemer of the spend handler.
pub type WhatRedeemer {
  /// One block. Spends the tip.
  ///
  /// There is no payout index: the payout rule has to scan every output
  /// anyway, to prove the reward output is the only one holding WHAT.
  Block {
    /// The 80-byte header, in Bitcoin's exact wire format.
    header: ByteArray,
    /// The coinbase commitment whose SHA-256d is the header's merkle root.
    coinbase: ByteArray,
  }
}

/// Redeemer of the mint handler. The ledger runs the policy once per
/// transaction, so each of these fixes the *whole* mint under the policy, and
/// no transaction can do both.
pub type MintRedeemer {
  /// Mint the genesis state-thread token. Possible once, and only in the
  /// transaction that spends the validator's `genesis_utxo` parameter.
  Genesis
  /// Mint one block reward. Carries the reference of the tip UTxO being spent
  /// so the policy can read the height it is paying for without trusting the
  /// spend handler.
  Mine { state_ref: OutputReference }
}
