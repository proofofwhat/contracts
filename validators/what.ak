//// Proof of What? -- the whole chain.
////
//// One validator, so the script hash is both the WHAT minting policy id and
//// the address the tip UTxO lives at. The tip UTxO carries a state-thread
//// token and a `State` datum; a block is a transaction that spends it with an
//// 80-byte Bitcoin header as redeemer.
////
//// Everything the chain needs beyond the lottery -- ordering, finality,
//// double-spend prevention, timekeeping -- is Cardano's. Two miners who solve
//// the same height race to spend one UTxO and the loser's transaction is
//// simply invalid, which is why WHAT has no forks of its own.
////
//// The reward is paid to the address the work commits to, under the datum the
//// work commits to, and the validator knows nothing about who or what owns
//// that address. A wallet, a multisig, a DAO treasury and
//// an account contract deployed long after genesis are all just addresses.

use aiken/builtin
use aiken/collection/dict
use aiken/collection/list
use aiken/interval.{
  Finite, Interval, IntervalBound, NegativeInfinity, PositiveInfinity,
}
use aiken/math.{pow2}
use aiken/primitive/bytearray
use cardano/address.{Address, Inline, Script, VerificationKey}
use cardano/assets.{Assets, PolicyId, from_asset, without_lovelace}
use cardano/transaction.{
  Datum, DatumHash, InlineDatum, Input, NoDatum, Output, OutputReference,
  Transaction, find_input,
}
use what/coinbase.{Coinbase}
use what/difficulty
use what/header
use what/parameters.{
  halving_number, initial_payout, max_validity_span, pow_limit, target_spacing,
  tip_token_name, token_name,
}
use what/types.{
  Block, Genesis, Mine, MintRedeemer, State, Tip, WhatDatum, WhatRedeemer,
}

/// `initial_target` is T0: the base target the genesis datum starts from.
/// It is a parameter rather than a constant because it is a launch-day
/// judgement about how much hashpower will actually show up (whitepaper
/// section 6), and because it lets a devnet run the same code at a target a
/// CPU can find. Like the other two parameters it is baked into the script
/// hash, so it cannot be changed without changing the chain's identity.
validator what(
  genesis_utxo: OutputReference,
  genesis_hash: ByteArray,
  initial_target: Int,
) {
  /// Issuance. There is no mint path other than this one: no allocation
  /// table, no treasury, no premine.
  mint(redeemer: MintRedeemer, own_policy: PolicyId, self: Transaction) {
    when redeemer is {
      Genesis -> {
        let Transaction { inputs, outputs, mint, validity_range, .. } = self

        // Mint(0) Genesis: the parameterised UTxO is consumed, so the
        // state-thread token can be minted exactly once, ever.
        expect
          list.any(inputs, fn(input) { input.output_reference == genesis_utxo })

        // Mint(1) Genesis: the only thing minted is the state-thread token.
        expect [Pair(name, 1)] = mint
          |> assets.tokens(own_policy)
          |> dict.to_pairs
        expect name == tip_token_name

        // Mint(2) Genesis: it goes to the one output carrying it, which is at
        // our own address, alongside nothing but ada.
        let own_address = address.from_script(own_policy)

        expect [Output { datum: out_datum, value: out_value, reference_script, .. }] = list.filter(
          outputs,
          holds_the_tip(own_address, own_policy),
        )

        expect without_lovelace(out_value) == tip_value(own_policy)
        expect reference_script == None

        // Mint(3) Genesis: the genesis header's hash is the chain's first
        // prev_hash. Its coinbase commitment carries the launch-day headline,
        // which is public and needs no on-chain check.
        expect builtin.length_of_bytearray(genesis_hash) == 32

        // Mint(3b) Genesis: a starting target outside the protocol's range
        // would either make every hash a winner or stall the chain forever.
        expect initial_target >= 1
        expect initial_target <= pow_limit()

        let time = validity_start(validity_range)

        // Mint(4) Genesis: the datum sets the starting base target and the
        // time the first interval is measured from.
        expect InlineDatum(data) = out_datum
        expect datum: WhatDatum = data

        datum == Tip {
          state: State {
            block_number: 0,
            current_hash: genesis_hash,
            current_time: time,
            base_target: initial_target,
          },
        }
      }

      // The block reward. The spend handler below does the real work; this is
      // an independent check that the amount minted matches the height of the
      // tip UTxO actually being spent, so issuance does not rest on a single
      // script.
      Mine { state_ref } -> {
        let Transaction { inputs, mint, .. } = self

        expect Some(Input { output: state_output, .. }) = find_input(
          inputs,
          state_ref,
        )

        let Output { address: state_address, value: state_value, datum, .. } = state_output

        // Mint(0) Mine: the input is the tip UTxO of this very script.
        expect state_address == address.from_script(own_policy)
        expect assets.quantity_of(state_value, own_policy, tip_token_name) == 1

        expect InlineDatum(data) = datum
        expect Tip { state: State { block_number, .. } }: WhatDatum = data

        // Mint(1) Mine: one block reward for height block_number + 1, and
        // nothing else under the policy. The spend checks where it lands -- the
        // policy cannot see the commitment, and the spend cannot see the height
        // independently, so each checks the half it can.
        assets.tokens(mint, own_policy) == assets.tokens(
          reward_mint(own_policy, block_reward(block_number + 1)),
          own_policy,
        )
      }
    }
  }

  /// One rule: a block spends the tip.
  ///
  /// Only the UTxO holding the state-thread token under a `Tip` datum can be
  /// spent. An output at this address with no datum, or with a datum that is
  /// not a `Tip`, can never be spent, which is what makes publishing a
  /// reference script here permanent -- and what makes anything else sent here
  /// lost, exactly as it would be at any other address nobody can sign for.
  spend(
    datum: Option<WhatDatum>,
    redeemer: WhatRedeemer,
    own_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(Input { output: own_input, .. }) = find_input(self.inputs, own_ref)

    let Output { address: own_address, value: own_value, .. } = own_input

    expect Script(own_policy) = own_address.payment_credential

    expect Some(Tip { state }) = datum
    let Block { header: header_bytes, coinbase: coinbase_bytes } = redeemer

    block(
      state,
      header_bytes,
      coinbase_bytes,
      own_address,
      own_policy,
      own_value,
      self,
    )
  }

  else(_) {
    fail
  }
}

/// One block. Whitepaper section 5, numbered the same way.
fn block(
  state: State,
  header_bytes: ByteArray,
  coinbase_bytes: ByteArray,
  own_address: Address,
  own_policy: PolicyId,
  own_value: Assets,
  self: Transaction,
) -> Bool {
  let State { block_number, current_hash, current_time, base_target } = state

  let Transaction { outputs, validity_range, .. } = self

  // Spend(0): the tip UTxO is the one holding the state-thread token, and
  // exactly one output carries it onward.
  expect assets.quantity_of(own_value, own_policy, tip_token_name) == 1

  expect [Output { datum: out_datum, value: out_value, reference_script, .. }] = list.filter(
    outputs,
    holds_the_tip(own_address, own_policy),
  )

  // A reference script on the tip is a griefer's way to raise the next
  // block's fee by a quarter of an ada (F-10).
  expect reference_script == None

  // Cardano's clock. The validity-interval start is attested by the stake
  // pool that includes the transaction: it cannot be in the future, because
  // the ledger will not accept the transaction before it.
  let time = validity_start(validity_range)

  expect time >= current_time

  // The interval this block closes, by Cardano's attestation at both ends.
  // It is both the in-flight elapsed time and the interval the per-block
  // update is computed from -- one quantity, not two.
  let interval = time - current_time

  let height = block_number + 1
  let block = header.parse(header_bytes)
  let found = header.hash(header_bytes)
  let commitment = coinbase.parse(coinbase_bytes)

  and {
    // Spend(1): the header extends the stored tip.
    block.prev_hash == current_hash,
    // Spend(2): the work meets the target the header committed to.
    header.meets_target(found, block.target),
    // Spend(3): that target is no easier than the protocol allows at this
    // transaction's validity-interval start.
    block.target <= difficulty.allowed_target(base_target, interval),
    // Spend(4): the coinbase commitment carries the right chain tag and
    // height, and its hash is the header's merkle root. The tag and the
    // length checks live in `coinbase.parse`.
    commitment.height == height,
    coinbase.merkle_root(coinbase_bytes) == block.merkle_root,
    // Spend(5): exactly one block reward is minted, and it lands at the
    // address and under the datum committed inside the work.
    pays_the_winner(self, commitment, own_policy, height),
    // Spend(6): the new tip carries the state-thread token and nothing else.
    without_lovelace(out_value) == tip_value(own_policy),
    // Spend(7): the new tip records this block and carries the base target
    // the next block inherits -- looser if this block was slow, tighter if
    // it was fast.
    out_datum == InlineDatum(
      Tip {
        state: State {
          block_number: height,
          current_hash: found,
          current_time: time,
          base_target: difficulty.next_base_target(base_target, interval),
        },
      },
    ),
  }
}

/// Bitcoin's schedule: 50 WHAT, halved every 210,000 blocks, to zero.
pub fn block_reward(height: Int) -> Int {
  let halvings = height / halving_number

  if halvings > 32 {
    0
  } else {
    initial_payout / pow2(halvings)
  }
}

/// The mint a block must carry: the reward and nothing else. Empty at reward
/// zero.
fn reward_mint(own_policy: PolicyId, reward: Int) -> Assets {
  if reward == 0 {
    assets.zero
  } else {
    from_asset(own_policy, token_name, reward)
  }
}

/// The payout: whitepaper section 5, rule 5.
///
/// The reward lands in one output, at the committed address and under the
/// committed datum. That output may also absorb UTxOs already sitting at the
/// committed address -- an account being topped up, a miner merging their own
/// rewards -- and the rules guarantee a block can only ever add to them:
///
///  1. the mint is exactly the reward;
///  2. every spent input at the committed address that holds WHAT carries the
///     committed datum, so junk seeded there can never be merged, and no
///     reference script, which rule 6 would otherwise have the block drop;
///  3. exactly one output holds WHAT, at the committed address, under the
///     committed datum;
///  4. its assets other than ada and WHAT are exactly those of the inputs in
///     rule 2, so nothing is stuffed in and nothing is pulled out;
///  5. its ada is at least theirs, so a top-up is allowed and a skim is not;
///  6. it carries no reference script.
///
/// WHAT amounts are not compared, and do not need to be. The ledger keeps
/// WHAT out equal to WHAT in plus WHAT minted; rule 1 fixes the mint and rule
/// 3 leaves one place for WHAT to go, so the reward output holds every WHAT
/// input plus the reward -- in particular every WHAT of the inputs in rule 2.
/// WHAT spent from anywhere else ends up there too, which is a gift to the
/// winner, not a theft from them.
///
/// Inputs at the committed address that hold no WHAT are not constrained:
/// they are the owner's business, and a self-submitting miner's fee input is
/// one of them.
///
/// The committed address is never parsed. It is compared as the bytes
/// `serialise_data` produces, so the validator knows nothing about address
/// formats, and nothing about what any address belongs to.
fn pays_the_winner(
  self: Transaction,
  commitment: Coinbase,
  own_policy: PolicyId,
  height: Int,
) -> Bool {
  let reward = block_reward(height)
  let minted = assets.tokens(self.mint, own_policy)

  if reward == 0 {
    // Past the last halving there is nothing to mint and nothing to pay.
    minted == assets.tokens(assets.zero, own_policy)
  } else {
    let Coinbase { address: committed_address, datum: committed_datum, .. } =
      commitment

    // Rule 3: one output holds WHAT.
    expect [payout] =
      list.filter(
        self.outputs,
        fn(output) { holds_what(output.value, own_policy) },
      )

    // Rule 2, and the total the payout has to carry forward.
    let merged =
      list.foldr(
        self.inputs,
        assets.zero,
        fn(input, total) {
          let Output { address, value, datum, reference_script } = input.output
          if holds_what(value, own_policy) && builtin.serialise_data(address) == committed_address {
            expect coinbase.datum_hash(datum) == committed_datum
            // A stored script is not an asset, so rule 4 cannot carry it
            // forward, and rule 6 refuses it on the output: merging this input
            // would destroy it. Refused instead, so a block takes nothing out.
            expect reference_script == None
            assets.merge(total, value)
          } else {
            total
          }
        },
      )

    let Output { address, value, datum, reference_script } = payout

    and {
      // Rule 1.
      minted == assets.tokens(reward_mint(own_policy, reward), own_policy),
      // Rule 3.
      builtin.serialise_data(address) == committed_address,
      coinbase.datum_hash(datum) == committed_datum,
      // Rule 4. Compared by difference, so the order a builder wrote the
      // assets in cannot matter.
      assets.merge(
        others(value, own_policy),
        assets.negate(others(merged, own_policy)),
      ) == assets.zero,
      // Rule 5.
      assets.lovelace_of(value) >= assets.lovelace_of(merged),
      // Rule 6.
      reference_script == None,
    }
  }
}

fn holds_what(value: Assets, own_policy: PolicyId) -> Bool {
  assets.quantity_of(value, own_policy, token_name) > 0
}

/// Everything in a value except ada and WHAT.
fn others(value: Assets, own_policy: PolicyId) -> Assets {
  without_lovelace(value)
    |> assets.add(
        own_policy,
        token_name,
        -assets.quantity_of(value, own_policy, token_name),
      )
}

fn tip_value(own_policy: PolicyId) -> Assets {
  from_asset(own_policy, tip_token_name, 1)
}

/// Is this output the one carrying the state-thread token onward?
fn holds_the_tip(own_address: Address, own_policy: PolicyId) -> fn(Output) -> Bool {
  fn(output: Output) {
    output.address == own_address && assets.quantity_of(
      output.value,
      own_policy,
      tip_token_name,
    ) == 1
  }
}

/// The start of the transaction's validity interval, which is WHAT's only
/// clock. The span is bounded so that the time a block records cannot drift
/// far from when it was actually accepted.
fn validity_start(validity_range: Interval) -> Int {
  expect
      Interval {
        lower_bound: IntervalBound {
          bound_type: Finite(lower),
          is_inclusive: lower_is_inclusive,
        },
        upper_bound: IntervalBound {
          bound_type: Finite(upper),
          is_inclusive: upper_is_inclusive,
        },
      }
    = validity_range

  expect lower_is_inclusive
  expect !upper_is_inclusive
  expect upper - lower <= max_validity_span

  lower
}

test reward_schedule() {
  and {
    block_reward(1) == 5_000_000_000,
    block_reward(209_999) == 5_000_000_000,
    block_reward(210_000) == 2_500_000_000,
    block_reward(420_000) == 1_250_000_000,
    block_reward(210_000 * 32) == 1,
    block_reward(210_000 * 33) == 0,
  }
}

test supply_is_capped_near_21_million() {
  let total = list.foldl(
    list.range(0, 33),
    0,
    fn(halvings, acc) {
      acc + halving_number * block_reward(halvings * halving_number)
    },
  )

  // 20,999,999.9769 WHAT — Bitcoin's figure, and 50 more than this chain can
  // mint. The fold pays a reward at every height in era 0, but height 0 is
  // genesis and pays nothing, so era 0 pays 209,999 rewards and the real cap
  // is 20,999,949.9769. The bounds below are loose enough to hold either way.
  and {
    total <= 2_100_000_000_000_000,
    total > 2_099_999_900_000_000,
  }
}

// ## End-to-end tests
//
// One real WHAT block, mined for these tests at the protocol's own pow limit
// (nBits ffff7f20, so about every other nonce wins), then walked through the
// validator intact and with one thing wrong at a time. Its coinbase commits
// `miner_address` and `NoDatum`. The work check is real: `header.meets_target`
// runs on its actual hash.
//
// The payout rules are also exercised directly through `pays_the_winner`, with
// commitments that were never mined, so script owners, datums and an account
// contract are tested without paying for proof of work. Those tests show what
// the rules do *given* a commitment; the end-to-end ones show that the work
// binds it, which is why a copier cannot pick one.

const script_hash = #"5c5f5dcf5ca11c5bb1c1e73c85df0e9d4f0f2b9f6c0d1e2f3a4b5c6d"

const miner_vkh = #"00112233445566778899aabbccddeeff00112233445566778899aabb"

/// `builtin.serialise_data` of `address.from_verification_key(miner_vkh)`.
const miner_address =
  #"d8799fd8799f581c00112233445566778899aabbccddeeff00112233445566778899aabbffd87a80ff"

/// A script that might mine: a DAO treasury, an agent wallet, a contract
/// pool. To WHAT it is just an address.
const pool_script = #"aabbccddeeff00112233445566778899aabbccddeeff001122334455"

/// A test account contract. Never deployed: its block
/// path below exists to prove the validator leaves room for one.
const account_script =
  #"acc0acc0acc0acc0acc0acc0acc0acc0acc0acc0acc0acc0acc0acc0"

/// Somebody with no claim on anything here.
const thief = #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

/// Some other policy's tokens: dust, or an account contract's own NFT.
const junk_policy = #"1111111111111111111111111111111111111111111111111111111f"

/// Height 0, `miner_address`, `datum_hash(NoDatum)`, and the headline as its
/// extranonce, as the genesis tool builds it.
const genesis_coinbase =
  #"57484154000000000029d8799fd8799f581c00112233445566778899aabbccddeeff00112233445566778899aabbffd87a80ff923918e403bf43c34b4ef6b48eb2ee04babed17320d8d1b9ff9ad086e86f44ec50726f6f66206f6620576861743f2061736b732077686572652074686520776f726b20676f6573207768656e2061207365636f6e642062757965722061707065617273"

/// Version 1, a zero prev_hash, `genesis_coinbase`'s merkle root, the pow
/// limit and nonce 0: constructed, not mined (whitepaper section 4).
const genesis_header =
  #"0100000000000000000000000000000000000000000000000000000000000000000000000c5b93e2c15434c66cf906279720236f5107de326bd3a2bca807ea7808c867fd00000069ffff7f2000000000"

/// SHA-256d of `genesis_header`: the `genesis_hash` validator parameter.
const genesis_tip =
  #"8e1e13415cdd624c6309015b1aa5e0b3d64b776c2c69bce53e52ed848772bcfd"

/// Height 1, `miner_address`, `datum_hash(NoDatum)`, eight bytes of
/// extranonce.
const coinbase_1 =
  #"57484154000000010029d8799fd8799f581c00112233445566778899aabbccddeeff00112233445566778899aabbffd87a80ff923918e403bf43c34b4ef6b48eb2ee04babed17320d8d1b9ff9ad086e86f44ec0000000000000000"

const header_1 =
  #"040000008e1e13415cdd624c6309015b1aa5e0b3d64b776c2c69bce53e52ed848772bcfd630a16585dc78febd2a7081ea7dbe5aca0ea2a25064dc8351af90f96dfdc7faa00000069ffff7f2000000000"

const reward_1 = 5_000_000_000

/// The devnet and the tests both start at the pow limit, the easiest target
/// the protocol allows.
const test_initial_target = pow_limit()

const t0 = 1_800_000_000_000

/// `header_1` commits the pow-limit target, which is what `initial_target` is
/// in these tests, so the block is valid the instant it is found. Half the
/// target interval, so it is a *fast* block: from the pow limit the base can
/// only tighten, and an on-time block would leave it unchanged and test
/// nothing.
const t1 = t0 + target_spacing / 2

const tip_ref =
  OutputReference {
    transaction_id: #"0000000000000000000000000000000000000000000000000000000000000001",
    output_index: 0,
  }

const prior_ref =
  OutputReference {
    transaction_id: #"0000000000000000000000000000000000000000000000000000000000000002",
    output_index: 0,
  }

const other_ref =
  OutputReference {
    transaction_id: #"0000000000000000000000000000000000000000000000000000000000000003",
    output_index: 0,
  }

/// The min-ada a WHAT output carries. Quantity-independent, so one deposit
/// covers any balance.
const deposit = 2_000_000

fn own() -> Address {
  address.from_script(script_hash)
}

fn wallet(vkh: ByteArray) -> Address {
  address.from_verification_key(vkh)
}

/// Where a miner's account sits under the test account contract: the
/// contract pays, the owner's payment credential stakes.
fn account_address(vkh: ByteArray) -> Address {
  Address {
    payment_credential: Script(account_script),
    stake_credential: Some(Inline(VerificationKey(vkh))),
  }
}

fn genesis_state() -> State {
  State {
    block_number: 0,
    current_hash: genesis_tip,
    current_time: t0,
    base_target: test_initial_target,
  }
}

fn tip_input(state: State) -> Input {
  Input { output_reference: tip_ref, output: tip_output(state) }
}

fn tip_output(state: State) -> Output {
  Output {
    address: own(),
    value: assets.from_lovelace(2_000_000)
      |> assets.add(script_hash, tip_token_name, 1),
    datum: InlineDatum(Tip { state }),
    reference_script: None,
  }
}

fn what_value(what: Int, lovelace: Int) -> Assets {
  assets.from_lovelace(lovelace)
    |> assets.add(script_hash, token_name, what)
}

/// A foreign token on top of whatever is there.
fn dusted(value: Assets) -> Assets {
  value |> assets.add(junk_policy, #"01", 1)
}

fn output_at(address: Address, value: Assets) -> Output {
  Output { address, value, datum: NoDatum, reference_script: None }
}

/// An ordinary output paying `vkh`, with no datum: what a wallet receives.
fn paying(vkh: ByteArray, value: Assets) -> Output {
  output_at(wallet(vkh), value)
}

fn input(reference: OutputReference, output: Output) -> Input {
  Input { output_reference: reference, output }
}

fn at(time: Int) -> Interval {
  Interval {
    lower_bound: IntervalBound { bound_type: Finite(time), is_inclusive: True },
    upper_bound: IntervalBound {
      bound_type: Finite(time + 120_000),
      is_inclusive: False,
    },
  }
}

fn mint_reward(reward: Int) -> Assets {
  assets.from_asset(script_hash, token_name, reward)
}

/// The reward block 1 pays: straight into the miner's wallet.
fn reward_output() -> Output {
  paying(miner_vkh, what_value(reward_1, deposit))
}

/// The transaction that submits block 1, assembled so each test can bend one
/// part of it.
fn block_tx(
  state: State,
  next: State,
  payout: Output,
  mint: Assets,
  time: Int,
) -> Transaction {
  Transaction {
    ..transaction.placeholder,
    inputs: [tip_input(state)],
    outputs: [tip_output(next), payout],
    mint: mint,
    validity_range: at(time),
  }
}

/// Block 1 exactly as it should be, at `t1`.
fn block_1_tx() -> Transaction {
  block_tx(
    genesis_state(),
    next_state(header.hash(header_1), t1),
    reward_output(),
    mint_reward(reward_1),
    t1,
  )
}

/// Block 1 with its payout replaced.
fn block_1_paying(payout: Output) -> Transaction {
  Transaction {
    ..block_1_tx(),
    outputs: [tip_output(next_state(header.hash(header_1), t1)), payout],
  }
}

/// The tip datum block 1 must write: the base target moves by the law, from
/// the interval Cardano attested at both ends.
fn next_state(found: ByteArray, time: Int) -> State {
  State {
    block_number: 1,
    current_hash: found,
    current_time: time,
    base_target: difficulty.next_base_target(test_initial_target, time - t0),
  }
}

fn redeemer_1() -> WhatRedeemer {
  Block { header: header_1, coinbase: coinbase_1 }
}

/// The UTxO the validator is parameterised by, consumed at genesis.
const genesis_utxo =
  OutputReference {
    transaction_id: #"0000000000000000000000000000000000000000000000000000000000000000",
    output_index: 0,
  }

fn spend_with(
  datum: Option<WhatDatum>,
  own_ref: OutputReference,
  tx: Transaction,
) -> Bool {
  what.spend(
    genesis_utxo,
    genesis_tip,
    test_initial_target,
    datum,
    redeemer_1(),
    own_ref,
    tx,
  )
}

fn spend_block(state: State, redeemer: WhatRedeemer, tx: Transaction) -> Bool {
  what.spend(
    genesis_utxo,
    genesis_tip,
    test_initial_target,
    Some(Tip { state }),
    redeemer,
    tip_ref,
    tx,
  )
}

fn spend_block_1(tx: Transaction) -> Bool {
  spend_block(genesis_state(), redeemer_1(), tx)
}

fn minting(redeemer: MintRedeemer, tx: Transaction) -> Bool {
  what.mint(
    genesis_utxo,
    genesis_tip,
    test_initial_target,
    redeemer,
    script_hash,
    tx,
  )
}

// ### Blocks

/// `genesis_tip` is derived, not a bare constant: it is the hash of a header
/// committing a height-0 coinbase that carries the headline.
test the_genesis_hash_commits_the_headline() {
  let committed = coinbase.parse(genesis_coinbase)

  and {
    header.hash(genesis_header) == genesis_tip,
    header.parse(genesis_header).prev_hash == #"0000000000000000000000000000000000000000000000000000000000000000",
    coinbase.merkle_root(genesis_coinbase) == header.parse(genesis_header).merkle_root,
    committed.height == 0,
    committed.address == miner_address,
    committed.datum == coinbase.datum_hash(NoDatum),
  }
}

/// Every `fail` test below that builds on block 1 assumes the fixture is
/// otherwise valid. If `header_1` goes stale against `coinbase_1`, they all
/// fail at the merkle root and pass for the wrong reason; this one says so.
test the_fixture_header_binds_the_fixture_coinbase() {
  and {
    coinbase.merkle_root(coinbase_1) == header.parse(header_1).merkle_root,
    header.parse(header_1).prev_hash == genesis_tip,
    header.meets_target(header.hash(header_1), header.parse(header_1).target),
  }
}

test accepts_a_valid_block() {
  spend_block_1(block_1_tx())
}

test mint_handler_accepts_the_same_block() {
  minting(Mine { state_ref: tip_ref }, block_1_tx())
}

test the_coinbase_commits_the_serialised_address_and_no_datum() {
  let committed = coinbase.parse(coinbase_1)

  and {
    committed.address == miner_address,
    committed.address == builtin.serialise_data(wallet(miner_vkh)),
    committed.datum == coinbase.datum_hash(NoDatum),
  }
}

test rejects_a_block_that_does_not_extend_the_tip() fail {
  let orphaned = State {
    ..genesis_state(),
    current_hash: header.hash(header_1),
  }

  let tx = block_tx(
    orphaned,
    next_state(header.hash(header_1), t1),
    reward_output(),
    mint_reward(reward_1),
    t1,
  )

  spend_block(orphaned, redeemer_1(), tx)
}

test rejects_a_target_easier_than_allowed() fail {
  // A chain launched at the reference mainnet target: the pow-limit target
  // `header_1` commits to is far too easy, and submitting on schedule gives
  // the in-flight law no time to loosen it.
  let strict = State {
    ..genesis_state(),
    base_target: parameters.reference_initial_target(),
  }

  let tx = block_tx(
    strict,
    State {
      ..next_state(header.hash(header_1), t0 + target_spacing),
      base_target: parameters.reference_initial_target(),
    },
    reward_output(),
    mint_reward(reward_1),
    t0 + target_spacing,
  )

  what.spend(
    genesis_utxo,
    genesis_tip,
    parameters.reference_initial_target(),
    Some(Tip { state: strict }),
    redeemer_1(),
    tip_ref,
    tx,
  )
}

/// `header_1` with nonce 1: the same version, prev hash, merkle root and
/// nBits, but a hash above the pow-limit target it commits.
const header_1_unworked =
  #"040000008e1e13415cdd624c6309015b1aa5e0b3d64b776c2c69bce53e52ed848772bcfd630a16585dc78febd2a7081ea7dbe5aca0ea2a25064dc8351af90f96dfdc7faa00000069ffff7f2001000000"

/// Block 1 submitted under `h` and `cb`, with the tip datum recording `h`'s
/// hash, so nothing but the header and coinbase can tell two such blocks apart.
fn block_1_under(h: ByteArray, cb: ByteArray) -> Bool {
  let tx = block_tx(
    genesis_state(),
    next_state(header.hash(h), t1),
    reward_output(),
    mint_reward(reward_1),
    t1,
  )

  spend_block(genesis_state(), Block { header: h, coinbase: cb }, tx)
}

test rejects_a_header_that_misses_its_own_target() fail {
  block_1_under(header_1_unworked, coinbase_1)
}

test the_unworked_twin_differs_only_in_work() {
  // Proves the test above fails at Spend(2) and nowhere else.
  let worked = header.parse(header_1)
  let unworked = header.parse(header_1_unworked)

  and {
    bytearray.take(header_1_unworked, 76) == bytearray.take(header_1, 76),
    unworked.target == worked.target,
    !header.meets_target(header.hash(header_1_unworked), unworked.target),
    block_1_under(header_1, coinbase_1),
  }
}

test rejects_minting_more_than_the_reward() fail {
  let tx = block_tx(
    genesis_state(),
    next_state(header.hash(header_1), t1),
    paying(miner_vkh, what_value(reward_1 + 1, deposit)),
    mint_reward(reward_1 + 1),
    t1,
  )

  spend_block_1(tx)
}

test rejects_burning_what() fail {
  // The mint has to equal the reward exactly, so a negative quantity is
  // refused. Supply can only ever go up, on the schedule, which is the other
  // half of the cap argument.
  let tx = block_tx(
    genesis_state(),
    next_state(header.hash(header_1), t1),
    reward_output(),
    mint_reward(-reward_1),
    t1,
  )

  spend_block_1(tx)
}

test rejects_a_block_that_mints_nothing() fail {
  // With no mint the policy never runs, so the spend has to refuse it: a
  // block that moved the tip without paying would take a height's reward out
  // of the schedule.
  let tx = block_tx(
    genesis_state(),
    next_state(header.hash(header_1), t1),
    reward_output(),
    assets.zero,
    t1,
  )

  spend_block_1(tx)
}

test rejects_a_tip_datum_that_does_not_move_the_base_target() fail {
  // A fast block has to tighten the base. Carrying it forward unchanged --
  // which is what the old absolute-anchor rule did -- is now invalid.
  let unchanged = State {
    ..next_state(header.hash(header_1), t1),
    base_target: test_initial_target,
  }

  let tx = block_tx(
    genesis_state(),
    unchanged,
    reward_output(),
    mint_reward(reward_1),
    t1,
  )

  spend_block_1(tx)
}

test a_fast_block_hands_on_a_tighter_base_target() {
  // Block 1 arrived at half the target interval, so the base it hands to
  // block 2 is tighter by 2^(1/2) -- the rule reacting to hashpower within a
  // single block, which is the whole point of section 6.
  let next = next_state(header.hash(header_1), t1)

  // Tolerance is one part in a thousand: the cubic approximation of 2^x is
  // least accurate at exactly the half-way point this test sits on, where its
  // relative error reaches 0.013%.
  and {
    next.base_target < test_initial_target,
    next.base_target * 141_421 / 100_000 > test_initial_target * 999 / 1000,
    next.base_target * 141_421 / 100_000 < test_initial_target * 1001 / 1000,
  }
}

test rejects_a_block_whose_timestamp_goes_backwards() fail {
  let tx = block_tx(
    genesis_state(),
    next_state(header.hash(header_1), t0 - 1),
    reward_output(),
    mint_reward(reward_1),
    t0 - 1,
  )

  spend_block_1(tx)
}

/// `coinbase_1` committing height 2 instead of 1, and nothing else changed.
const coinbase_2 =
  #"57484154000000020029d8799fd8799f581c00112233445566778899aabbccddeeff00112233445566778899aabbffd87a80ff923918e403bf43c34b4ef6b48eb2ee04babed17320d8d1b9ff9ad086e86f44ec0000000000000000"

/// A header mined over `coinbase_2`: `header_1` with `coinbase_2`'s merkle
/// root, and nonce 0 still meets the pow limit. Real work on the wrong height.
const header_1_at_height_2 =
  #"040000008e1e13415cdd624c6309015b1aa5e0b3d64b776c2c69bce53e52ed848772bcfd5661a35bcf9362fac42ed4326b656fc9645bfb3963fb95f205a7588652a498d400000069ffff7f2000000000"

test rejects_a_coinbase_for_the_wrong_height() fail {
  // Height 2 committed while the tip is still 0. The merkle root matches and
  // the work is real, so only the height check can refuse it.
  block_1_under(header_1_at_height_2, coinbase_2)
}

test the_wrong_height_twin_differs_only_in_height() {
  // Proves the test above fails at the height check and nowhere else.
  let mined = header.parse(header_1_at_height_2)

  and {
    bytearray.take(coinbase_2, 4) == bytearray.take(coinbase_1, 4),
    bytearray.drop(coinbase_2, 8) == bytearray.drop(coinbase_1, 8),
    mined.merkle_root == coinbase.merkle_root(coinbase_2),
    header.meets_target(header.hash(header_1_at_height_2), mined.target),
    block_1_under(header_1, coinbase_1),
  }
}

test rejects_a_block_that_skips_a_height() fail {
  // The supply cap rests on height advancing by exactly one per mint: the
  // reward is a function of height, so a block that jumped two heights would
  // mint one reward while moving the schedule twice, and a chain that could
  // jump heights could mint past 21,000,000. Spend(7) pins it.
  let skipped = State {
    ..next_state(header.hash(header_1), t1),
    block_number: 3,
  }

  let tx = block_tx(
    genesis_state(),
    skipped,
    reward_output(),
    mint_reward(reward_1),
    t1,
  )

  spend_block_1(tx)
}

// ### The copier
//
// Somebody takes `header_1` and `coinbase_1` out of the mempool and rebuilds
// the transaction. The work binds the address and the datum, so neither can
// move; everything else the copier controls is what the payout rules are for.

test a_copied_block_cannot_pay_another_address() fail {
  spend_block_1(block_1_paying(paying(thief, what_value(reward_1, deposit))))
}

test a_copied_block_cannot_pay_the_winner_under_another_stake_part() fail {
  // Same payment key, different address: the commitment is the whole address.
  spend_block_1(
    block_1_paying(
      output_at(
        address.with_delegation_key(wallet(miner_vkh), thief),
        what_value(reward_1, deposit),
      ),
    ),
  )
}

test a_copied_block_cannot_attach_a_datum() fail {
  // Harmless to a key wallet, but the same move against a script owner is a
  // datum its validator might never accept.
  spend_block_1(
    block_1_paying(
      Output { ..reward_output(), datum: InlineDatum(builtin.i_data(0)) },
    ),
  )
}

test a_copied_block_cannot_attach_a_datum_hash() fail {
  spend_block_1(
    block_1_paying(Output { ..reward_output(), datum: DatumHash(genesis_tip) }),
  )
}

test a_copied_block_cannot_split_the_reward() fail {
  // Rule 3: one output holds WHAT. Half to the winner, half to the copier.
  let tx = Transaction {
    ..block_1_tx(),
    outputs: [
      tip_output(next_state(header.hash(header_1), t1)),
      paying(miner_vkh, what_value(reward_1 / 2, deposit)),
      paying(thief, what_value(reward_1 / 2, deposit)),
    ],
  }

  spend_block_1(tx)
}

test the_reward_cannot_be_split_even_at_the_committed_address() fail {
  // Rule 3 counts WHAT outputs, not WHAT outputs elsewhere: two halves both
  // paying the winner are still two.
  let tx = Transaction {
    ..block_1_tx(),
    outputs: [
      tip_output(next_state(header.hash(header_1), t1)),
      paying(miner_vkh, what_value(reward_1 / 2, deposit)),
      paying(miner_vkh, what_value(reward_1 / 2, deposit)),
    ],
  }

  spend_block_1(tx)
}

test a_copied_block_cannot_stuff_the_reward_output() fail {
  // Rule 4.
  spend_block_1(
    block_1_paying(paying(miner_vkh, dusted(what_value(reward_1, deposit)))),
  )
}

test a_copied_block_cannot_attach_a_reference_script() fail {
  // Rule 6. Plutus V1 cannot spend an output carrying one.
  spend_block_1(
    block_1_paying(
      Output { ..reward_output(), reference_script: Some(pool_script) },
    ),
  )
}

test the_submitter_may_add_ada_to_the_reward() {
  // Rule 5 is a floor: whoever funds the block decides the deposit.
  spend_block_1(
    block_1_paying(paying(miner_vkh, what_value(reward_1, 5_000_000))),
  )
}

test the_submitter_may_take_change_and_pay_others() {
  // Outputs holding no WHAT are none of the validator's business.
  let tx = Transaction {
    ..block_1_tx(),
    outputs: [
      tip_output(next_state(header.hash(header_1), t1)),
      reward_output(),
      paying(thief, assets.from_lovelace(50_000_000)),
      paying(thief, dusted(assets.from_lovelace(2_000_000))),
    ],
  }

  spend_block_1(tx)
}

// ### Merging
//
// A block may spend WHAT-holding UTxOs already at the committed address --
// here a self-submitting miner folding their earlier rewards into this one.

/// Block 1, also spending `merged` and paying `payout`.
fn merging_block_1(merged: List<Input>, payout: Output) -> Transaction {
  Transaction {
    ..block_1_paying(payout),
    inputs: [tip_input(genesis_state()), ..merged],
  }
}

fn earlier_reward(reference: OutputReference, what: Int) -> Input {
  input(reference, paying(miner_vkh, what_value(what, deposit)))
}

test a_block_may_merge_earlier_rewards() {
  spend_block_1(
    merging_block_1(
      [earlier_reward(prior_ref, 100), earlier_reward(other_ref, 200)],
      paying(miner_vkh, what_value(reward_1 + 300, 2 * deposit)),
    ),
  )
}

test a_merge_cannot_keep_only_one_deposit() fail {
  // Rule 5: two deposits in, one out, and the submitter pockets the other.
  spend_block_1(
    merging_block_1(
      [earlier_reward(prior_ref, 100), earlier_reward(other_ref, 200)],
      paying(miner_vkh, what_value(reward_1 + 300, 2 * deposit - 1)),
    ),
  )
}

test a_merge_carries_other_assets_through() {
  // Rule 4 is equality, not "ada and WHAT only": what came in goes out. This
  // is what lets an account contract's own NFT ride along.
  spend_block_1(
    merging_block_1(
      [input(prior_ref, paying(miner_vkh, dusted(what_value(100, deposit))))],
      paying(miner_vkh, dusted(what_value(reward_1 + 100, deposit))),
    ),
  )
}

test a_merge_cannot_pull_assets_out() fail {
  spend_block_1(
    merging_block_1(
      [input(prior_ref, paying(miner_vkh, dusted(what_value(100, deposit))))],
      paying(miner_vkh, what_value(reward_1 + 100, deposit)),
    ),
  )
}

test a_merge_cannot_add_assets_either() fail {
  spend_block_1(
    merging_block_1(
      [input(prior_ref, paying(miner_vkh, dusted(what_value(100, deposit))))],
      paying(
        miner_vkh,
        dusted(what_value(reward_1 + 100, deposit))
          |> assets.add(junk_policy, #"02", 1),
      ),
    ),
  )
}

test a_merge_cannot_take_an_input_under_another_datum() fail {
  // Rule 2. `coinbase_1` commits `NoDatum`.
  spend_block_1(
    merging_block_1(
      [
        input(
          prior_ref,
          Output {
            ..paying(miner_vkh, what_value(100, deposit)),
            datum: InlineDatum(builtin.i_data(7)),
          },
        ),
      ],
      paying(miner_vkh, what_value(reward_1 + 100, deposit)),
    ),
  )
}

test a_merge_cannot_drop_a_stored_reference_script() fail {
  // A UTxO at the committed address that keeps a script for later use. Rule 6
  // keeps the script off the reward output, so merging the UTxO would destroy
  // it; rule 2 refuses the merge instead.
  spend_block_1(
    merging_block_1(
      [
        input(
          prior_ref,
          Output {
            ..paying(miner_vkh, what_value(100, deposit)),
            reference_script: Some(pool_script),
          },
        ),
      ],
      paying(miner_vkh, what_value(reward_1 + 100, deposit)),
    ),
  )
}

test a_merge_without_a_stored_script_is_allowed() {
  // The twin: the same merge with only the reference script removed passes,
  // so the test above fails at the reference-script check and nowhere else.
  // A UTxO that does store a script is left where it is, and the block pays
  // the reward beside it, as `accepts_a_valid_block` does.
  spend_block_1(
    merging_block_1(
      [input(prior_ref, paying(miner_vkh, what_value(100, deposit)))],
      paying(miner_vkh, what_value(reward_1 + 100, deposit)),
    ),
  )
}

test inputs_without_what_are_not_constrained() {
  // A self-submitting miner's fee input: ada at the committed address, under
  // any datum, with its change going wherever the miner likes.
  let fee =
    input(
      prior_ref,
      Output {
        ..paying(miner_vkh, dusted(assets.from_lovelace(20_000_000))),
        datum: InlineDatum(builtin.i_data(7)),
      },
    )

  let tx = Transaction {
    ..merging_block_1([fee], reward_output()),
    outputs: [
      tip_output(next_state(header.hash(header_1), t1)),
      reward_output(),
      paying(thief, dusted(assets.from_lovelace(17_000_000))),
    ],
  }

  spend_block_1(tx)
}

test what_from_elsewhere_is_a_gift() {
  // WHAT spent from another address can only go to the winner. Whoever owns
  // that address had to agree to spend it; an account contract that lets
  // anyone spend in a block refuses exactly this (`account_block_path`).
  spend_block_1(
    merging_block_1(
      [input(prior_ref, paying(thief, what_value(100, deposit)))],
      paying(miner_vkh, what_value(reward_1 + 100, deposit)),
    ),
  )
}

// ### Script owners
//
// Commitments nobody mined, through `pays_the_winner` directly.

fn commitment(to: Address, datum: Datum) -> Coinbase {
  Coinbase {
    height: 1,
    address: builtin.serialise_data(to),
    datum: coinbase.datum_hash(datum),
  }
}

/// A block-1-shaped transaction spending `merged` and paying `outputs`.
fn payout_tx(merged: List<Input>, outputs: List<Output>) -> Transaction {
  Transaction {
    ..transaction.placeholder,
    inputs: [tip_input(genesis_state()), ..merged],
    outputs: [tip_output(next_state(header.hash(header_1), t1)), ..outputs],
    mint: mint_reward(reward_1),
  }
}

fn pays(c: Coinbase, tx: Transaction) -> Bool {
  pays_the_winner(tx, c, script_hash, 1)
}

fn treasury() -> Address {
  address.from_script(pool_script)
}

fn treasury_datum() -> Datum {
  InlineDatum(builtin.constr_data(0, [builtin.b_data(#"da0da0")]))
}

fn to_treasury(value: Assets, datum: Datum) -> Output {
  Output { address: treasury(), value, datum, reference_script: None }
}

test a_treasury_receives_under_its_own_datum() {
  pays(
    commitment(treasury(), treasury_datum()),
    payout_tx(
      [],
      [to_treasury(what_value(reward_1, deposit), treasury_datum())],
    ),
  )
}

test a_treasury_reward_cannot_arrive_without_its_datum() fail {
  pays(
    commitment(treasury(), treasury_datum()),
    payout_tx([], [to_treasury(what_value(reward_1, deposit), NoDatum)]),
  )
}

test a_treasury_reward_cannot_arrive_under_a_junk_datum() fail {
  pays(
    commitment(treasury(), treasury_datum()),
    payout_tx(
      [],
      [
        to_treasury(
          what_value(reward_1, deposit),
          InlineDatum(builtin.i_data(0)),
        ),
      ],
    ),
  )
}

test junk_seeded_at_a_treasury_cannot_be_merged() fail {
  // An attacker sends a little WHAT to the treasury under a datum of their
  // own. Even if the treasury's script would let a copier spend it, rule 2
  // refuses the merge, so the reward cannot be carried off under that datum.
  let junk =
    input(
      prior_ref,
      to_treasury(what_value(1, deposit), InlineDatum(builtin.i_data(0))),
    )

  pays(
    commitment(treasury(), treasury_datum()),
    payout_tx(
      [junk],
      [to_treasury(what_value(reward_1 + 1, deposit), treasury_datum())],
    ),
  )
}

test junk_seeded_at_a_treasury_is_simply_left_out() {
  // The twin of the test above: the same block without the junk input.
  pays(
    commitment(treasury(), treasury_datum()),
    payout_tx(
      [],
      [to_treasury(what_value(reward_1, deposit), treasury_datum())],
    ),
  )
}

test a_v1_owner_commits_a_datum_hash() {
  // Plutus V1 cannot spend an inline datum, so it commits the hash form.
  let hashed =
    DatumHash(
      #"d00dd00dd00dd00dd00dd00dd00dd00dd00dd00dd00dd00dd00dd00dd00dd00d",
    )

  pays(
    commitment(treasury(), hashed),
    payout_tx([], [to_treasury(what_value(reward_1, deposit), hashed)]),
  )
}

test a_hash_commitment_is_not_met_by_the_inline_datum() fail {
  let d = builtin.i_data(5)

  pays(
    commitment(
      treasury(),
      DatumHash(builtin.blake2b_256(builtin.serialise_data(d))),
    ),
    payout_tx([], [to_treasury(what_value(reward_1, deposit), InlineDatum(d))]),
  )
}

test a_reward_to_this_script_is_not_refused() {
  // Committing the WHAT script's own address loses the reward -- nothing but
  // the tip is ever spendable here -- exactly as any payment to it would. The
  // validator does not try to save the committer from it.
  pays(
    commitment(own(), NoDatum),
    payout_tx([], [output_at(own(), what_value(reward_1, deposit))]),
  )
}

// ### An account contract
//
// `account_block_path` is one path of a test account contract, written as a
// plain function: anyone may spend an account in a
// block, provided the block mints WHAT, some output at the account's own
// address holds WHAT, and the account itself holds WHAT. It never ships. These
// tests prove the WHAT validator leaves room for one, and that path (b) is
// safe on top of the six rules.

fn account_block_path(own_ref: OutputReference, tx: Transaction) -> Bool {
  expect Some(Input { output: own_input, .. }) = find_input(tx.inputs, own_ref)

  and {
    assets.quantity_of(tx.mint, script_hash, token_name) > 0,
    holds_what(own_input.value, script_hash),
    list.any(
      tx.outputs,
      fn(output) {
        output.address == own_input.address && holds_what(
          output.value,
          script_hash,
        )
      },
    ),
  }
}

/// An account: ada, WHAT, and the account contract's own NFT. No datum.
fn account_value(what: Int, lovelace: Int) -> Assets {
  what_value(what, lovelace) |> assets.add(account_script, #"a1", 1)
}

fn account_of(vkh: ByteArray, what: Int) -> Output {
  output_at(account_address(vkh), account_value(what, deposit))
}

test a_block_tops_up_an_account() {
  // The deposit is recycled: no new UTxO, no new min-ada.
  let tx =
    payout_tx(
      [input(prior_ref, account_of(miner_vkh, 1_000))],
      [account_of(miner_vkh, 1_000 + reward_1)],
    )

  and {
    pays(commitment(account_address(miner_vkh), NoDatum), tx),
    account_block_path(prior_ref, tx),
  }
}

test a_first_block_to_an_account_needs_no_account_input() {
  // Nothing to create and nothing to name: the reward just lands at the
  // account address. The first one costs a deposit; every later one merges.
  pays(
    commitment(account_address(miner_vkh), NoDatum),
    payout_tx(
      [],
      [output_at(account_address(miner_vkh), what_value(reward_1, deposit))],
    ),
  )
}

test a_block_may_merge_two_account_utxos() {
  // A pool payout that arrived as its own UTxO is folded in by the next block.
  let tx =
    payout_tx(
      [
        input(prior_ref, account_of(miner_vkh, 1_000)),
        input(
          other_ref,
          output_at(account_address(miner_vkh), what_value(50, deposit)),
        ),
      ],
      [
        output_at(
          account_address(miner_vkh),
          account_value(1_050 + reward_1, 2 * deposit),
        ),
      ],
    )

  and {
    pays(commitment(account_address(miner_vkh), NoDatum), tx),
    account_block_path(prior_ref, tx),
    account_block_path(other_ref, tx),
  }
}

test an_accounts_nft_cannot_be_dropped() fail {
  let tx =
    payout_tx(
      [input(prior_ref, account_of(miner_vkh, 1_000))],
      [
        output_at(
          account_address(miner_vkh),
          what_value(1_000 + reward_1, deposit),
        ),
      ],
    )

  pays(commitment(account_address(miner_vkh), NoDatum), tx)
}

test an_accounts_deposit_cannot_be_skimmed() fail {
  let tx =
    payout_tx(
      [input(prior_ref, account_of(miner_vkh, 1_000))],
      [
        output_at(
          account_address(miner_vkh),
          account_value(1_000 + reward_1, deposit - 1),
        ),
      ],
    )

  pays(commitment(account_address(miner_vkh), NoDatum), tx)
}

/// A block won by the miner that also spends the thief's account: its WHAT
/// lands in the miner's wallet, its NFT and deposit go somewhere else (rule 4
/// would refuse them in the reward output).
fn sweeping_tx() -> Transaction {
  payout_tx(
    [input(other_ref, account_of(thief, 1_000))],
    [
      paying(miner_vkh, what_value(1_000 + reward_1, deposit)),
      paying(
        miner_vkh,
        assets.from_lovelace(deposit) |> assets.add(account_script, #"a1", 1),
      ),
    ],
  )
}

test another_owners_account_cannot_be_swept_into_a_block() fail {
  // The WHAT validator alone allows it: that input is not at the committed
  // address, so to the six rules its WHAT is a gift to the winner. Path (b)
  // is what refuses it, because the only WHAT output is not at that account's
  // address.
  and {
    pays(commitment(wallet(miner_vkh), NoDatum), sweeping_tx()),
    account_block_path(other_ref, sweeping_tx()),
  }
}

test another_owners_account_is_refused_by_path_b_alone() {
  // The twin: the six rules pass and path (b) fails, which is the claim above.
  and {
    pays(commitment(wallet(miner_vkh), NoDatum), sweeping_tx()),
    !account_block_path(other_ref, sweeping_tx()),
  }
}

test an_empty_account_cannot_be_spent_by_a_block() {
  // An account holding no WHAT is outside rule 2, so nothing would protect
  // its ada or its NFT; path (b) refuses it instead.
  let tx =
    payout_tx(
      [input(prior_ref, account_of(miner_vkh, 0))],
      [account_of(miner_vkh, reward_1)],
    )

  !account_block_path(prior_ref, tx)
}

// ### The tip output

test rejects_a_tip_output_with_a_reference_script() fail {
  // A 16 KB script attached to the tip raises the next block's fee by about a
  // quarter of an ada, every block, forever (F-10).
  let tx = Transaction {
    ..block_1_tx(),
    outputs: [
      Output {
        ..tip_output(next_state(header.hash(header_1), t1)),
        reference_script: Some(pool_script),
      },
      reward_output(),
    ],
  }

  spend_block_1(tx)
}

test rejects_a_tip_output_holding_anything_else() fail {
  let tx = Transaction {
    ..block_1_tx(),
    outputs: [
      Output {
        ..tip_output(next_state(header.hash(header_1), t1)),
        value: dusted(
          assets.from_lovelace(2_000_000)
            |> assets.add(script_hash, tip_token_name, 1),
        ),
      },
      reward_output(),
    ],
  }

  spend_block_1(tx)
}

test rejects_a_tip_output_holding_the_reward() fail {
  // The tip is never the reward output.
  let tx = Transaction {
    ..block_1_tx(),
    outputs: [
      Output {
        ..tip_output(next_state(header.hash(header_1), t1)),
        value: assets.from_lovelace(2_000_000)
          |> assets.add(script_hash, tip_token_name, 1)
          |> assets.add(script_hash, token_name, reward_1),
      },
    ],
  }

  spend_block_1(tx)
}

test rejects_a_tip_output_at_another_address() fail {
  // The filter finds no output carrying the token at our address, so there is
  // no next tip at all.
  let tx = Transaction {
    ..block_1_tx(),
    outputs: [
      Output {
        ..tip_output(next_state(header.hash(header_1), t1)),
        address: address.with_delegation_key(own(), miner_vkh),
      },
      reward_output(),
    ],
  }

  spend_block_1(tx)
}

test rejects_a_tip_output_with_a_datum_hash() fail {
  let tx = Transaction {
    ..block_1_tx(),
    outputs: [
      Output {
        ..tip_output(next_state(header.hash(header_1), t1)),
        datum: DatumHash(genesis_tip),
      },
      reward_output(),
    ],
  }

  spend_block_1(tx)
}

// ### Reward zero and the halving boundary
//
// Exercised through `pays_the_winner` directly: a block at height 210,000 * 33
// would need a coinbase committing that height, and so a header mined against
// it.

test the_last_paying_height_still_pays() {
  let height = 210_000 * 33 - 1
  let reward = block_reward(height)

  let tx = Transaction {
    ..transaction.placeholder,
    inputs: [tip_input(genesis_state())],
    outputs: [paying(miner_vkh, what_value(reward, deposit))],
    mint: mint_reward(reward),
  }

  and {
    reward == 1,
    pays_the_winner(tx, coinbase.parse(coinbase_1), script_hash, height),
  }
}

test past_the_last_halving_nothing_is_minted_and_nothing_is_paid() {
  let tx = Transaction { ..transaction.placeholder, outputs: [] }

  and {
    block_reward(210_000 * 33) == 0,
    pays_the_winner(tx, coinbase.parse(coinbase_1), script_hash, 210_000 * 33),
  }
}

test past_the_last_halving_nothing_may_be_minted() fail {
  let tx = Transaction {
    ..transaction.placeholder,
    mint: assets.from_asset(script_hash, token_name, 1),
  }

  pays_the_winner(tx, coinbase.parse(coinbase_1), script_hash, 210_000 * 33)
}

// ### Dispatch

test only_the_tip_can_be_spent() fail {
  // A `Tip` datum on a UTxO that does not hold the state-thread token is just
  // a datum.
  let fake =
    input(
      prior_ref,
      Output {
        address: own(),
        value: assets.from_lovelace(2_000_000),
        datum: InlineDatum(Tip { state: genesis_state() }),
        reference_script: None,
      },
    )

  spend_with(
    Some(Tip { state: genesis_state() }),
    prior_ref,
    Transaction { ..block_1_tx(), inputs: [fake] },
  )
}

test a_utxo_without_a_datum_at_the_script_is_never_spendable() fail {
  // A reward committed to this address, or anything else sent here.
  let lost = input(prior_ref, output_at(own(), what_value(reward_1, deposit)))

  spend_with(
    None,
    prior_ref,
    Transaction { ..block_1_tx(), inputs: [tip_input(genesis_state()), lost] },
  )
}

// ### Genesis
//
// Possible once, in the transaction that spends the parameterised UTxO.

fn genesis_tx(outputs: List<Output>, mint: Assets, time: Int) -> Transaction {
  Transaction {
    ..transaction.placeholder,
    inputs: [
      Input {
        output_reference: genesis_utxo,
        output: paying(miner_vkh, assets.from_lovelace(10_000_000)),
      },
    ],
    outputs: outputs,
    mint: mint,
    validity_range: at(time),
  }
}

fn tip_mint() -> Assets {
  assets.from_asset(script_hash, tip_token_name, 1)
}

fn genesis_mint(hash: ByteArray, target: Int, tx: Transaction) -> Bool {
  what.mint(genesis_utxo, hash, target, Genesis, script_hash, tx)
}

test genesis_opens_the_chain() {
  let tx = genesis_tx([tip_output(genesis_state())], tip_mint(), t0)

  genesis_mint(genesis_tip, test_initial_target, tx)
}

test genesis_needs_the_parameterised_utxo() fail {
  // Without it the state-thread token could be minted again, which is a
  // second chain under the same policy id.
  let tx = Transaction {
    ..genesis_tx([tip_output(genesis_state())], tip_mint(), t0),
    inputs: [
      Input {
        output_reference: tip_ref,
        output: paying(miner_vkh, assets.from_lovelace(10_000_000)),
      },
    ],
  }

  genesis_mint(genesis_tip, test_initial_target, tx)
}

test genesis_cannot_premine() fail {
  // No allocation table, no treasury, no premine: the only thing this mint
  // may produce is the tip token.
  let tx = genesis_tx(
    [
      tip_output(genesis_state()),
      paying(miner_vkh, what_value(1_000_000, deposit)),
    ],
    tip_mint() |> assets.add(script_hash, token_name, 1_000_000),
    t0,
  )

  genesis_mint(genesis_tip, test_initial_target, tx)
}

test genesis_cannot_mint_two_tips() fail {
  let tx = genesis_tx(
    [
      tip_output(genesis_state()),
      Output {
        ..tip_output(genesis_state()),
        value: assets.from_lovelace(2_000_000)
          |> assets.add(script_hash, tip_token_name, 1),
      },
    ],
    assets.from_asset(script_hash, tip_token_name, 2),
    t0,
  )

  genesis_mint(genesis_tip, test_initial_target, tx)
}

test genesis_cannot_mint_another_token() fail {
  let tx = genesis_tx(
    [
      tip_output(genesis_state()),
      paying(
        miner_vkh,
        assets.from_lovelace(deposit) |> assets.add(script_hash, #"a1", 1),
      ),
    ],
    tip_mint() |> assets.add(script_hash, #"a1", 1),
    t0,
  )

  genesis_mint(genesis_tip, test_initial_target, tx)
}

test the_genesis_datum_records_the_validity_start() fail {
  // The chain's clock starts at Cardano's attestation of when it started, not
  // at a number the founder picked.
  let tx = genesis_tx([tip_output(genesis_state())], tip_mint(), t0 + 1)

  genesis_mint(genesis_tip, test_initial_target, tx)
}

test the_genesis_datum_carries_the_parameters() fail {
  let wrong = State { ..genesis_state(), base_target: test_initial_target - 1 }

  let tx = genesis_tx([tip_output(wrong)], tip_mint(), t0)

  genesis_mint(genesis_tip, test_initial_target, tx)
}

test the_genesis_datum_starts_at_height_zero() fail {
  let wrong = State { ..genesis_state(), block_number: 1 }

  let tx = genesis_tx([tip_output(wrong)], tip_mint(), t0)

  genesis_mint(genesis_tip, test_initial_target, tx)
}

test the_genesis_hash_must_be_a_sha256d() fail {
  // Anything else and the first header's `prev_hash` could never match it.
  let short = #"4d52c67f135b8a051215ddbe98954e7d"

  let state = State { ..genesis_state(), current_hash: short }

  let tx = genesis_tx([tip_output(state)], tip_mint(), t0)

  genesis_mint(short, test_initial_target, tx)
}

test the_genesis_target_cannot_be_zero() fail {
  // A target of zero stalls the chain forever: no hash is ever below it.
  let state = State { ..genesis_state(), base_target: 0 }

  let tx = genesis_tx([tip_output(state)], tip_mint(), t0)

  genesis_mint(genesis_tip, 0, tx)
}

test the_genesis_target_cannot_exceed_the_pow_limit() fail {
  // Past the pow limit nBits cannot even encode the target a block would have
  // to commit to.
  let state = State { ..genesis_state(), base_target: pow_limit() + 1 }

  let tx = genesis_tx([tip_output(state)], tip_mint(), t0)

  genesis_mint(genesis_tip, pow_limit() + 1, tx)
}

test the_genesis_tip_holds_nothing_but_its_token() fail {
  let tx = genesis_tx(
    [
      Output {
        ..tip_output(genesis_state()),
        value: dusted(
          assets.from_lovelace(2_000_000)
            |> assets.add(script_hash, tip_token_name, 1),
        ),
      },
    ],
    tip_mint(),
    t0,
  )

  genesis_mint(genesis_tip, test_initial_target, tx)
}

test the_genesis_tip_carries_no_reference_script() fail {
  let tx = genesis_tx(
    [
      Output {
        ..tip_output(genesis_state()),
        reference_script: Some(pool_script),
      },
    ],
    tip_mint(),
    t0,
  )

  genesis_mint(genesis_tip, test_initial_target, tx)
}

// ### The Mine policy
//
// An independent check that the amount minted matches the height of the tip
// UTxO actually being spent, so issuance does not rest on a single script.

test mine_needs_the_real_tip() fail {
  // A `Tip` datum on a UTxO that does not hold the state-thread token is just
  // a datum. Without the token check, any height could be claimed.
  let fake = Input {
    output_reference: tip_ref,
    output: Output {
      address: own(),
      value: assets.from_lovelace(2_000_000),
      datum: InlineDatum(Tip { state: genesis_state() }),
      reference_script: None,
    },
  }

  let tx = Transaction { ..block_1_tx(), inputs: [fake] }

  minting(Mine { state_ref: tip_ref }, tx)
}

test mine_needs_the_tip_at_this_script() fail {
  let elsewhere = Input {
    output_reference: tip_ref,
    output: Output { ..tip_output(genesis_state()), address: wallet(miner_vkh) },
  }

  let tx = Transaction { ..block_1_tx(), inputs: [elsewhere] }

  minting(Mine { state_ref: tip_ref }, tx)
}

test mine_needs_its_state_ref_to_be_an_input() fail {
  minting(Mine { state_ref: other_ref }, block_1_tx())
}

test mine_cannot_mint_a_second_tip() fail {
  let tx = Transaction {
    ..block_1_tx(),
    mint: mint_reward(reward_1) |> assets.add(script_hash, tip_token_name, 1),
  }

  minting(Mine { state_ref: tip_ref }, tx)
}

test mine_cannot_mint_another_token() fail {
  let tx = Transaction {
    ..block_1_tx(),
    mint: mint_reward(reward_1) |> assets.add(script_hash, #"a1", 1),
  }

  minting(Mine { state_ref: tip_ref }, tx)
}

test mine_cannot_mint_more_than_the_reward() fail {
  let tx = Transaction { ..block_1_tx(), mint: mint_reward(reward_1 + 1) }

  minting(Mine { state_ref: tip_ref }, tx)
}

// ### Time
//
// The validity-interval start is Cardano's attestation of when a block
// landed, and it is the chain's only clock.

fn block_1_at(range: Interval) -> Bool {
  spend_block_1(Transaction { ..block_1_tx(), validity_range: range })
}

test a_block_needs_a_finite_lower_bound() fail {
  block_1_at(
    Interval {
      lower_bound: IntervalBound {
        bound_type: NegativeInfinity,
        is_inclusive: True,
      },
      upper_bound: IntervalBound {
        bound_type: Finite(t1 + 120_000),
        is_inclusive: False,
      },
    },
  )
}

test a_block_needs_a_finite_upper_bound() fail {
  // An open-ended interval would let a block record a time arbitrarily far
  // from when it was accepted.
  block_1_at(
    Interval {
      lower_bound: IntervalBound { bound_type: Finite(t1), is_inclusive: True },
      upper_bound: IntervalBound {
        bound_type: PositiveInfinity,
        is_inclusive: False,
      },
    },
  )
}

test a_block_needs_an_inclusive_lower_bound() fail {
  // The ledger presents a closed lower bound and an open upper one. Any other
  // shape and the time this block records is not the one it was validated at.
  block_1_at(
    Interval {
      lower_bound: IntervalBound { bound_type: Finite(t1), is_inclusive: False },
      upper_bound: IntervalBound {
        bound_type: Finite(t1 + 120_000),
        is_inclusive: False,
      },
    },
  )
}

test a_block_needs_an_exclusive_upper_bound() fail {
  block_1_at(
    Interval {
      lower_bound: IntervalBound { bound_type: Finite(t1), is_inclusive: True },
      upper_bound: IntervalBound {
        bound_type: Finite(t1 + 120_000),
        is_inclusive: True,
      },
    },
  )
}

test a_block_cannot_span_more_than_two_minutes() fail {
  block_1_at(
    Interval {
      lower_bound: IntervalBound { bound_type: Finite(t1), is_inclusive: True },
      upper_bound: IntervalBound {
        bound_type: Finite(t1 + max_validity_span + 1),
        is_inclusive: False,
      },
    },
  )
}

// ### Header and coinbase edges

test nbits_at_the_pow_limit_decodes_to_it() {
  // 0x207fffff: the largest target nBits can encode, which is exactly the
  // protocol's pow limit.
  header.decode_bits(#"ffff7f20") == pow_limit()
}

test nbits_below_exponent_three_is_refused() fail {
  header.decode_bits(#"01000002") > 0
}

test nbits_above_exponent_thirty_two_is_refused() fail {
  // Past 32 the target would not fit in 256 bits.
  header.decode_bits(#"01000021") > 0
}

test a_coinbase_may_commit_a_height_above_two_to_the_twenty_four() {
  // Four big-endian bytes, so the field runs to 2^32. Bitcoin's three-byte
  // height encoding is not the constraint here.
  coinbase.parse(bytearray.concat(#"57484154010000010004deadbeef", padding(1))).height == 16_777_217
}

test a_coinbase_over_the_length_cap_is_refused() fail {
  // The parse is bounded so a block cannot be made expensive to validate.
  coinbase.parse(bytearray.concat(#"57484154000000010004deadbeef", padding(8))).height == 1
}

test an_address_over_the_length_cap_is_refused() fail {
  // 0x0081 is 129 bytes, one past the cap, in a commitment that is otherwise
  // well inside the length limit.
  coinbase.parse(bytearray.concat(#"5748415400000001008100", padding(6))).height == 1
}

/// `chunks` 32-byte chunks of zeroes.
fn padding(chunks: Int) -> ByteArray {
  list.foldl(
    list.range(1, chunks),
    #"",
    fn(_i, acc) {
      bytearray.concat(
        acc,
        #"0000000000000000000000000000000000000000000000000000000000000000",
      )
    },
  )
}

// ### Encodings
//
// The off-chain node builds these bytes independently, from its own encoder. A
// different-but-equivalent encoding on either side is a datum or redeemer the
// validator refuses, so: one hex literal, asserted from both sides.
// the node's own test suite holds the other half. The datum commitment is pinned
// in `lib/what/coinbase.ak`.

test the_tip_datum_is_pinned() {
  let state = State {
    block_number: 0,
    current_hash: genesis_tip,
    current_time: 1_800_000_000_000,
    base_target: parameters.reference_initial_target(),
  }

  builtin.serialise_data(Tip { state }) == #"d8799fd8799f0058208e1e13415cdd624c6309015b1aa5e0b3d64b776c2c69bce53e52ed848772bcfd1b000001a3185c5000c2581b010000000000000000000000000000000000000000000000000000ffff"
}

test the_block_redeemer_is_pinned() {
  builtin.serialise_data(
    Block { header: #"2222222222222222", coinbase: #"33333333" },
  ) == #"d8799f4822222222222222224433333333ff"
}

test the_mint_redeemers_are_pinned() {
  and {
    builtin.serialise_data(Genesis) == #"d87980",
    builtin.serialise_data(Mine { state_ref: tip_ref }) == #"d87a9fd8799f5820000000000000000000000000000000000000000000000000000000000000000100ffff",
  }
}

test others_drops_ada_and_what_and_nothing_else() {
  let value =
    what_value(5, deposit)
      |> assets.add(junk_policy, #"01", 3)
      |> assets.add(script_hash, tip_token_name, 1)

  others(value, script_hash) == (
    assets.from_asset(junk_policy, #"01", 3)
      |> assets.add(script_hash, tip_token_name, 1)
  )
}

// ### Budgets
//
// `aiken check` reports mem and cpu per test. Rules 2 and 3 scan every input
// and output, so the cost grows with what a block merges.

fn merging_n(n: Int) -> Bool {
  let refs =
    list.map(
      list.range(1, n),
      fn(i) {
        OutputReference {
          transaction_id: builtin.blake2b_256(builtin.serialise_data(i)),
          output_index: 0,
        }
      },
    )

  let tx =
    merging_block_1(
      list.map(refs, fn(r) { earlier_reward(r, 100) }),
      paying(miner_vkh, what_value(reward_1 + 100 * n, deposit * n)),
    )

  and {
    spend_block_1(tx),
    minting(Mine { state_ref: tip_ref }, tx),
  }
}

test budget_block() {
  let tx = block_1_tx()

  and {
    spend_block_1(tx),
    minting(Mine { state_ref: tip_ref }, tx),
  }
}

test budget_block_merging_one() {
  merging_n(1)
}

test budget_block_merging_five() {
  merging_n(5)
}

test budget_block_merging_twenty() {
  merging_n(20)
}
