# Security

This repository is a Plutus validator that controls the issuance of a token and
the state of a chain. A flaw in it is worth reporting.

## Reporting

Use GitHub's **private vulnerability reporting** on this repository (the
*Security* tab → *Report a vulnerability*). Please do not open a public issue.

There is no bounty. Reports are read and acknowledged.

## What a finding here costs

Worth knowing before you report, because it shapes what a fix can be: **the
validator's hash is the chain's identity.** It is simultaneously the WHAT
minting policy id and the address the tip UTxO lives at. Changing a single byte
of the script produces a different policy id — which is a different chain, with
a different token, and no migration path from the old one. So a fix is not a
patch release; it is a new chain. Report accordingly, and expect that to be the
first thing weighed.

## In scope

- **`validators/what.ak`** — the spend and mint handlers, the six payout rules
  in `pays_the_winner`, and the genesis path.
- **`lib/what/header.ak`** — 80-byte header parsing, SHA-256d, and the nBits
  encoding and its bounds.
- **`lib/what/difficulty.ak`** — the target rule. Anything that lets a miner
  claim a target easier than the chain allows at its transaction's validity
  start, or that makes the rule disagree with `lib/what/parity.ak`.
- **`lib/what/coinbase.ak`** — the commitment layout, and the datum hash.
- **`lib/what/parameters.ak`** — the schedule, the clamps, and the supply cap.

Specifically valuable: anything that lets a block be accepted whose header does
not meet its own claimed target; anything that mints more than the height's
reward, or mints at a height already paid; anything that lets a block move
value *out* of a UTxO already at the committed address; and anything that lets
the tip be spent other than by a block.

## Out of scope

These are deliberate and documented, not defects:

- **Committing the validator's own address as the payout address loses the
  reward.** Nothing but the tip is ever spendable there, and the validator does
  not try to save a committer from it.
- **Anything else sent to the script address is unrecoverable**, for the same
  reason. That is what makes a published reference script permanent.
- **The genesis headline is unchecked.** It is a timestamp, not a rule.
- **Whoever creates a chain can mine on the genesis hash before submitting
  genesis.** A head start of that interval's own length — see whitepaper §7.
  There is no on-chain fix and the paper says so.
- **The extranonce is bytes the validator never reads**, so another chain could
  take WHAT's headers as auxiliary proof of work. Whitepaper §11 covers what
  that does and does not change.
- **WHAT is never burned.** No mint path permits a negative quantity. Deliberate,
  and it means there is no path to destroy supply later.
- **The off-chain software is not in this repository**, so bugs in a Stratum
  server or transaction builder are not reportable here.

## Supported versions

The tip of `main`, built with Aiken v1.1.24. There are no releases.
