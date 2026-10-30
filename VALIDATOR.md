# WHAT validator

The Aiken contract for Proof of What?, implementing whitepaper sections 4 to 7.
The reward is paid straight to the committed address, and there is no account
layer in the validator.

```
lib/what/parameters.ak   protocol constants (baked into the script hash)
lib/what/types.ak        the datum and redeemer types
lib/what/header.ak       80-byte Bitcoin header parsing, SHA-256d, nBits
lib/what/coinbase.ak     coinbase commitment parsing and the datum commitment
lib/what/difficulty.ak   the symmetric per-block target rule
validators/what.ak       the validator, plus end-to-end tests
```

```sh
aiken check    # the validator's own tests
aiken build
```

## Shape

One validator, so its script hash is simultaneously the WHAT minting policy id
and the address the tip UTxO sits at. Three handlers:

- `mint(Genesis)` — consumes the UTxO the validator is parameterised by, mints
  the single `tip` state-thread token, and writes the genesis datum. Possible
  exactly once.
- `mint(Mine)` — mints one block reward and nothing else, checked
  independently against the height recorded in the tip UTxO the transaction is
  spending.
- `spend` — one rule: a block spends the tip.

The reward is Bitcoin's schedule unchanged: **50 WHAT at height 1, halved every
210,000 blocks, to zero** — eight decimals, so `initial_payout` is
5,000,000,000 base units and `block_reward` shifts it right by `height /
halving_number`. The cap is 20,999,949.9769 WHAT, fifty below Bitcoin's,
because the genesis header at height 0 mints nothing. Both constants are in
`lib/what/parameters.ak` and are baked into the script hash.

`Tip` is the only datum: tip height, tip hash, the tip's Cardano-attested time,
and the base target. That is the whole of the difficulty state — the rule is
relative to the last block, so `base_target` and `current_time` together
determine the target every miner is working against at any instant. Nothing
else at the script address can ever be spent: an output with no datum, or
without the tip token, matches nothing. That is what makes a published
reference script permanent, and what makes anything else sent here lost.

**The preimage is an unmodified Bitcoin header.** The work is SHA-256d over 80
bytes in Bitcoin's exact wire format, and the validator slices the fields it
constrains straight out of those bytes (`lib/what/header.ak`) rather than
destructuring a record. Nothing about the hash input is WHAT-specific, so stock
SHA-256d hardware mines it over ordinary Stratum with one configuration change.
That compatibility is the point of the project: a hash can only be spent here
by choosing this chain over whatever else the rig was doing.

**Targets are integers, read from the header's own nBits.** Plutus V3's
`byteStringToInteger` lets the hash be read as a little-endian integer —
exactly as Bitcoin reads it — and compared against the target its `bits` field
encodes. So the threshold checked on chain is bit-for-bit the one the miner's
hardware was handed, with no second representation to disagree with it.

## Difficulty

One symmetric law in log space, applied on every block, with no epoch and no
retarget interval (`lib/what/difficulty.ak`, whitepaper section 6):

    T_allowed(e) = T * 2^(max(0, e - S) / H)        in flight
    T            = T * 2^((interval - S) / H)       on a block

`T` is the base target from the tip datum, `e` the time elapsed since the tip,
`S` the target spacing and `H` the half-life. All four times are in
milliseconds, as `lib/what/parameters.ak` holds them: `target_spacing` and
`half_life` are both 600,000, so the half-life equals the target spacing.

The first line is a closed-form function of the clock that each miner evaluates
locally: while a block is in flight the allowed target eases continuously, with
no difficulty state changing and no Cardano transaction in between. The second
is the only state change there is. For a late block the two coincide exactly,
so the law is continuous through a slow block; for an early block the in-flight
term is inert and the update tightens the base by the mirror of the decay a
late block would have earned. That symmetry is what makes the controller
unbiased. The exponential is evaluated with the cubic approximation from
Bitcoin Cash's `aserti3-2d`.

The rule is relative to the last block and keeps no memory of cumulative
schedule error: it controls the block *rate*, not the block *count*. An
absolute anchor at genesis would additionally repay the `log2(k) * H / 600`
blocks a surge pulls forward — at H = 10 minutes that factor is 1, about seven
blocks for a hundredfold surge — so the property costs more than it buys, and
Bitcoin's own retarget does not have it either.

A consequence worth stating: because the allowed target never tightens with
elapsed time, a hash that met the target at discovery still meets it when the
transaction lands twenty seconds later.

## The coinbase commits an address and a datum

```
| offset  | bytes | field                                                |
|---------|-------|------------------------------------------------------|
|       0 |     4 | chain tag, "WHAT"                                    |
|       4 |     4 | block height, big-endian                             |
|       8 |     2 | address length N, big-endian                         |
|      10 |     N | payout address, `serialise_data` of the `Address`    |
|  10 + N |    32 | blake2b_256(serialise_data(payout output's datum))   |
|  42 + N |    .. | miner extranonce space                               |
```

The datum hash covers the whole datum *field* — `NoDatum`, `DatumHash(h)` or
`InlineDatum(d)` — so it is 32 bytes whatever the datum is, and "no datum" is a
commitment like any other. A wallet commits `NoDatum`; a script that needs
datum `d` commits `InlineDatum(d)`; a Plutus V1 script commits `DatumHash(h)`.
The bytes hashed are `serialise_data`'s, so the off-chain side must hash the
same canonical encoding; `lib/what/coinbase.ak` pins the vectors.

The commitment is per coinbase, not per address: an endpoint builds one for
each job, so an owner whose datum varies from block to block commits the right
one each time.

**The layout is fixed, which is what forecloses merged mining.** There is no
room in it for an auxiliary-proof-of-work structure, and `prev_hash` must equal
the WHAT tip, so a hash spent on WHAT cannot also count toward a Bitcoin block.
That exclusivity is what makes WHAT's hashrate a measurement of hashpower that
chose WHAT rather than a by-product of hashpower doing something else.

## The payout rules

When the reward is above zero, the block transaction must satisfy all six
(`pays_the_winner`):

1. The mint under the policy is exactly `{WHAT: reward}`.
2. Every spent input at the committed address that holds WHAT carries a datum
   whose hash is the committed one, and no reference script (merging it would
   drop the script, since rule 6 keeps scripts off the output).
3. Exactly one output holds WHAT. It is at the committed address, under the
   committed datum.
4. That output's assets other than ada and WHAT equal those of the inputs in
   rule 2: nothing added, nothing removed.
5. Its ada is at least theirs.
6. It carries no reference script.

Together they mean a block can deliver the reward to the committed address
under the committed datum, and may fold in UTxOs already sitting there, but can
never take anything out of them. A copier who lifts a solution out of the
mempool can change neither the address nor the datum, because the work binds
both; everything else they control is what rules 2 to 6 are for.

**The payout address is inside the work, so the submitter need not be the
winner.** The winner's Cardano address sits in the coinbase commitment whose
SHA-256d is the header's merkle root, and these rules require the reward to
land there, under the datum the commitment also carries. Change either and the
merkle root changes, so the header changes and the proof of work is gone.
Anyone may therefore submit anyone's block and it still pays its finder, which
is why front-running a solution out of the mempool buys nothing — and why
mining to yourself and mining through a Stratum endpoint are the same mechanism
rather than two code paths.

**WHAT amounts are not compared.** The ledger keeps WHAT out equal to WHAT in
plus WHAT minted. Rule 1 fixes the mint and rule 3 leaves one place for WHAT to
go, so the reward output holds every WHAT input plus the reward. WHAT spent from
some other address ends up there too: a gift to the winner, which its owner had
to agree to.

**Inputs at the committed address that hold no WHAT are unconstrained.** They
are the owner's business; a self-submitting miner's fee input is one.

**Who pays the fee and the minimum ada is not the validator's business.** Rule
5 lets ada in, so a solo miner funds their own block, an endpoint funds it from
its operator's wallet or from any arrangement it has with the miner, and a
block paying into an existing UTxO recycles that UTxO's deposit.

A native token cannot sit in an output without ada, so every reward carries
some. For a solo miner paying themselves it merely moves to their own address
and the real cost is the fee. An endpoint committing a *stranger's* address
funds about 1.5 ada a block that leaves for the miner and stays theirs —
unless the block folds the reward into a UTxO already at that address, under a
separate account contract, whose deposit every block then recycles.

## Owners

To the validator every owner is an address. Scripts that only *receive* need
nothing WHAT-specific: the committed datum makes every reward spendable under
their own rules. A script needs to know about WHAT only to let blocks fold
rewards into a UTxO it already has.

| Owner | Commits | Notes |
|---|---|---|
| Key wallet, native-script multisig | its address, `NoDatum` | Each block is a new UTxO. A copier cannot spend its inputs. |
| Plutus V2/V3 treasury needing datum `d` | its address, `InlineDatum(d)` | Junk seeded at the address under another datum cannot be merged (rule 2). |
| Plutus V1 script | its address, `DatumHash(h)` | Rule 6 keeps reference scripts, which V1 cannot spend past, off the output. |
| Account contract | the miner's account address, `NoDatum` | A separate contract, deployed after genesis; below. |
| Several payees | a splitter contract | One block, one payout output, by construction. |

### Accounts are a separate contract

The validator leaves room for an account contract without knowing it exists.
The tests carry one, `account_block_path`, which never ships: an account is a
UTxO at the account script with the owner's payment credential as stake part,
and *anyone* may spend it in a block, provided:

1. the transaction mints WHAT;
2. some output at the account's own address holds WHAT;
3. the account itself holds WHAT.

WHAT is minted only by a block, so (1) puts the six rules in force. Rule 3 says
the only WHAT output is at the committed address, so (2) means the account *is*
the committed address. With (3) the account falls under rule 2, and rules 4 and
5 hand it back with everything it held. A block won by somebody else cannot
spend it, because its only WHAT output is at the other owner's address
(`another_owners_account_cannot_be_swept_into_a_block`).

So the owner's deposit is recycled with no account token, no creation rule and
no contention: the block path only runs inside a real block, and
leaving the account out still pays the same address. The owner's own path —
withdraw, close — lives in that contract and can be fixed by deploying a new
one, which genesis cannot.

### Budgets

From the `budget_*` tests in `validators/what.ak`, as mem against the devnet's
10M per-transaction limit (14M on mainnet). They do not model the ScriptContext
overhead, so treat them as upper bounds on what fits:

| transaction | mem | cpu |
|---|---|---|
| a block | 0.79M | 0.25G |
| a block merging 1 earlier UTxO | 1.05M | 0.34G |
| a block merging 5 | 1.59M | 0.53G |
| a block merging 20 | 3.59M | 1.27G |

Both handlers are counted. Rules 2 and 3 scan every input and output, so the
cost grows with what a block merges.

### What is *not* on chain

A pool cannot split a reward on chain. The coinbase carries exactly one address
field and rule 3 allows one WHAT output. A pool is an operator who commits its
own address (or a pool contract's), keeps an off-chain share ledger, and pays
miners in ordinary transfers — and the skim is arithmetic it chooses,
unverifiable by the chain, because the chain cannot verify shares.

## Minimum work per block

The pow limit is `(2^23 - 1) * 2^232` — a full-width nBits mantissa at the
loosest exponent that still fits 256 bits, which is Bitcoin regtest's
`ffff7f20`: if nobody is hashing, the first hash that shows up
should win (`lib/what/parameters.ak` explains why there is no Bitcoin-style
floor). `initial_target` is the launch-day judgement; the devnet starts at the
pow limit, where about every other hash is a block and the rule tightens from
there.

`header_1` in `validators/what.ak` is a genuinely mined block at the pow limit,
with the chain tag, height 1, a test payout address and `NoDatum` committed in
its coinbase, so the work check runs on a real hash rather than a contrived
one.

## Prior art

Fortuna (`orbistry/fortuna`, TUNA) is the closest prior art: the same minimal
mechanism — a proof-of-work lottery over a Cardano state-thread UTxO — reached
from the thesis rather than from Fortuna's code. No code here derives from it,
though it shares some of Fortuna's vocabulary because it was a useful
comparison when auditing use cases.

The design above is the whole of what this validator does, so the differences
fall out of it rather than needing a list. Two are worth naming because they
are things Fortuna carries and this does not: the interlink / NIPoPoW vector
and the merkle-patricia-forestry block-history accumulator, and the hardfork,
migration and upgrade-nomination governance machinery — token votes, miner
votes, nomination tokens, thresholds. WHAT has no treasury, no allocation table
and nothing to vote on, so none of it has a counterpart. Fortuna also carries a
counter token so an immutable minting policy can learn the block height without
trusting an upgradeable spend script; this spend script is not upgradeable, so
the mint handler reads the height from the datum of the tip input it resolves
itself, and issuance is still checked twice by two handlers against two reads
of the same input.

What is common to both is what any proof-of-work lottery on Cardano converges
on: Bitcoin's issuance schedule, the state-thread-token pattern, a bounded
transaction validity interval, and the single-UTxO race that gives the chain
its finality. Whitepaper section 12 sets out the wider prior art — 0xBitcoin,
Minotaur, merged mining — and what this project claims over it.
