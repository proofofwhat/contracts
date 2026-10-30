# Proof of What? — the validator and the paper

**Proof of What? (WHAT)** is a Cardano native token whose issuance is handed out
by SHA-256d proof of work. Miners hash unmodified 80-byte Bitcoin headers; each
winning header goes to Cardano as a transaction, and this validator checks the
work and mints the block reward to a Cardano address committed inside the
header. Cardano does validation, ordering, double-spend prevention and
timekeeping. **The work only picks who gets the coinbase.**

This repository is the on-chain half: the Aiken validator, and the paper that
specifies it.

- [`whitepaper.md`](whitepaper.md) — the argument and the specification.
  Sections 4 to 7 are what the validator implements.
- [`VALIDATOR.md`](VALIDATOR.md) — how the validator works: the datum, the
  difficulty rule, the coinbase commitment, and the six payout rules.
- `validators/what.ak` — the validator. One script, three handlers.
- `lib/what/` — header parsing and SHA-256d, the nBits/target encoding, the
  difficulty rule, the coinbase commitment, and the datum and redeemer types.

It is published so the script can be read, built and checked against the chain
by anybody, without taking a policy id on trust.

## Build it

Needs [Aiken](https://aiken-lang.org/installation-instructions) **v1.1.24**. A
different compiler version can produce different bytes, and the bytes are the
chain's identity.

```sh
aikup install v1.1.24
aiken check      # the validator's own tests
aiken build      # writes plutus.json
jq -r '.validators[0].hash' plutus.json
```

Expect:

```
b67d2ad5a617642ad586fc1738e2ec947c7d2336ba7c1a36f23ac505
```

That is the **unapplied** validator — the script before a chain's parameters
are applied to it. All three handlers share it, since they are one script:
`plutus.json` lists `what.what.mint`, `what.what.spend` and `what.what.else`
with the same hash. `aiken blueprint hash` will not work yet — it only hashes a
fully applied validator, and this one still takes three parameters.

If your hash differs, your Aiken is not v1.1.24 or the source is not this
source. Either way nothing below will match.

### The toolchain the hash depends on

Three things outside this repository determine the bytes, so all three are
pinned here and worth checking if a hash ever disagrees:

| | | |
| -- | -- | -- |
| Aiken | `v1.1.24` | `aiken.toml`, and `aiken --version` should report `v1.1.24+bacbeb3` |
| Plutus version | `v3` | `aiken.toml` |
| `aiken-lang/stdlib` | `v4.0.0` | `aiken.toml` and `aiken.lock` |

Aiken resolves stdlib by **tag**, and a git tag is mutable, so the lockfile
alone does not fully pin it. For belt and braces, `v4.0.0` is commit
`dfdf5ffc4fa28896c075f06faf2bf6709a11cc5e` (tagged 2026-09-26). After a build
you can confirm you got the same one:

```sh
git -C build/packages/aiken-lang-stdlib rev-parse HEAD 2>/dev/null \
  || grep -m1 version build/packages/aiken-lang-stdlib/aiken.toml
```

## Verify a chain

The validator is parameterised by three values, so every chain gets its own
script and its own policy id. Applying them is how you check that a policy id
somebody handed you is really this code running on the parameters they claim.

Cardano's **Preview** testnet, the chain currently running:

| | |
| -- | -- |
| genesis UTxO | `6feead31a87305459b4c91a6357aa44056745aea63a3d7aa6943d4cdbfbde698#0` |
| genesis header hash | `6f42a91b0a95a61df1be68b7e75ba2e5403d738863b7f5fdc4185de6fee47103` |
| T0, the starting target | `2^208` |
| **policy id / script hash** | `af786bdfbbca193ceb8352b40576471c0ddca6d6261762448ad0397f` |
| genesis headline | `Bitzo 29/Oct/2026 Bitcoin Mining Profitability Falls Below $40 as Difficulty Climbs` |

Apply the three, in order, with Aiken and nothing else:

```sh
aiken build

# 1. the genesis UTxO, as an OutputReference
aiken blueprint apply -m what -v what -o /tmp/1.json \
  d8799f58206feead31a87305459b4c91a6357aa44056745aea63a3d7aa6943d4cdbfbde69800ff

# 2. the genesis header hash, 32 bytes
aiken blueprint apply -i /tmp/1.json -m what -v what -o /tmp/2.json \
  58206f42a91b0a95a61df1be68b7e75ba2e5403d738863b7f5fdc4185de6fee47103

# 3. T0 = 2^208
aiken blueprint apply -i /tmp/2.json -m what -v what -o /tmp/3.json \
  c2581b010000000000000000000000000000000000000000000000000000

aiken blueprint policy  -i /tmp/3.json -m what -v what
aiken blueprint address -i /tmp/3.json -m what -v what
```

Those print

```
af786bdfbbca193ceb8352b40576471c0ddca6d6261762448ad0397f
addr_test1wzhhs67lh09pj08tsdftgptkguwqmh9x6cnpwcjy3tgrjlcxuypv6
```

— the WHAT minting policy id, and the address the chain's tip UTxO sits at.
They are one script hash doing both jobs. The WHAT asset is that policy id
followed by `57484154`, the ascii for `WHAT`:

```
af786bdfbbca193ceb8352b40576471c0ddca6d6261762448ad0397f57484154
```

Look that up on any Preview explorer and you are looking at issuance this
script authorised. That history is also the paper's evidence: whitepaper
section 9 reads a hashprice off the reward, the difficulty each block was won
at, and how long the work kept turning up — all three of which are on chain
under this policy id, recorded by the rules above and by nothing else.

**A different genesis UTxO is a different chain**, by construction, with no
relationship to this one.

### The genesis headline

The genesis header commits a news headline from launch day, in the spirit of
Bitcoin's "Chancellor on brink" message. It timestamps the chain's start and
nothing in the validator checks it. It sits in the height-0 coinbase, whose
SHA-256d is the genesis header's merkle root, and the header's own SHA-256d is
the `genesis header hash` above — so the headline is bound to the policy id you
just derived, and cannot be restated later.

## Mining it

Nothing here is a mining client. The off-chain software a miner needs — a
Stratum server, the Cardano transaction builders, the node that submits blocks
— is still in development.

The protocol a client has to implement is specified regardless: section 4 of
the paper is the header and the coinbase commitment, section 5 is what a block
must satisfy, section 6 is the difficulty rule, and section 8 is how a Stratum
server hands work out. The validator is the authority on all four, and it is
here in full.

## Licence

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE). Vulnerability
reports: [`SECURITY.md`](SECURITY.md).
