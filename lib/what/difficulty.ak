//// The WHAT difficulty rule: one symmetric exponential law in log space,
//// evaluated against Cardano-attested time. No epoch and no retarget.
////
//// Whitepaper section 6. The chain carries a base target T and the Cardano
//// time of the last block. With e the time elapsed since that time, delta the
//// interval the submitted block closes, S the target spacing and H the
//// half-life -- all four in milliseconds, as `parameters.ak` holds them:
////
////     T_allowed(e) = T * 2^(max(0, e - S) / H)        in flight
////     T            = T * 2^((delta - S) / H)          on a block
////
//// The first is a closed-form function of the clock that every miner
//// evaluates locally: no difficulty state changes and no Cardano transaction
//// occurs between blocks. The second is the only state change, computed from
//// the on-chain timestamps alone.
////
//// For a late block the two coincide exactly -- `next_base_target` lands on
//// the target the block was already mined against -- so the law is continuous
//// through a slow block. For an early block the in-flight term is inert and
//// the update tightens the base by the mirror of the decay a late block would
//// have earned. That symmetry is what makes the controller unbiased: its
//// drift vanishes only where the mean interval equals the target.
////
//// There is no absolute anchor and no memory of cumulative schedule error.
//// The rule controls the block rate, not the block count; the supply cap is
//// held by the halving schedule, which is indexed on height, not time.
////
//// The exponential is evaluated the way Bitcoin Cash's aserti3-2d does it:
//// the integer part of the exponent becomes a shift, and the fractional part
//// goes through a cubic approximation of 2^x on [0, 1) whose relative error
//// stays under 0.013% -- small compared to the rounding that nBits' 24-bit
//// mantissa imposes on the target a miner can commit to anyway.

use aiken/builtin
use aiken/collection/list
use aiken/math.{pow2}
use what/parameters.{half_life, max_shift, pow_limit, target_spacing}

/// Hardest target the protocol will accept, so a clamped exponent can never
/// make a block free.
pub const min_target = 1

/// The largest target a block may commit to, given a base target carried from
/// the last block and the seconds elapsed since that block's Cardano time.
///
/// Non-decreasing in `elapsed`, which is the property miners rely on: the
/// target at confirmation is never harder than the target at discovery, so a
/// hash found and submitted still validates when it lands in the next Cardano
/// block some twenty seconds later.
pub fn allowed_target(base_target: Int, elapsed: Int) -> Int {
  let overdue = elapsed - target_spacing

  if overdue <= 0 {
    clamp(base_target)
  } else {
    scale_by_exp2(base_target, overdue)
  }
}

/// The base target the next block inherits, after a block closed an interval
/// of `interval` seconds. Loosens for a slow block, tightens for a fast one.
pub fn next_base_target(base_target: Int, interval: Int) -> Int {
  scale_by_exp2(base_target, interval - target_spacing)
}

/// `value * 2^(exponent / half_life)`, clamped to a sane target range.
fn scale_by_exp2(value: Int, exponent: Int) -> Int {
  // Floor division, so the remainder stays non-negative on both sides of zero
  // and the approximation below is only ever asked for 2^x on [0, 1).
  let shifts = builtin.divide_integer(exponent, half_life)
  let frac = builtin.mod_integer(exponent, half_life)

  if shifts >= max_shift {
    pow_limit()
  } else if shifts <= -max_shift {
    min_target
  } else {
    let scaled = value * two_to_the_fraction(frac)

    let target = if shifts >= 0 {
      scaled * pow2(shifts) / 65536
    } else {
      scaled / pow2(-shifts) / 65536
    }

    clamp(target)
  }
}

/// 2^(frac / half_life) in 16.16 fixed point, for 0 <= frac < half_life.
fn two_to_the_fraction(frac: Int) -> Int {
  let x = frac * 65536 / half_life

  65536 + (
    195766423245049 * x + 971821376 * x * x + 5127 * x * x * x + 140737488355328
  ) / 281474976710656
}

fn clamp(target: Int) -> Int {
  if target < min_target {
    min_target
  } else if target > pow_limit() {
    pow_limit()
  } else {
    target
  }
}

// A base target well inside the clamps, so the tests measure the law rather
// than the clamping. Bitcoin block 100,000's target.
const base = 0x4864c000000000000000000000000000000000000000000000000

// ## In flight

test flat_until_the_block_is_overdue() {
  and {
    allowed_target(base, 0) == base,
    allowed_target(base, target_spacing / 2) == base,
    allowed_target(base, target_spacing) == base,
  }
}

test loosens_once_overdue() {
  // One half-life past the target interval doubles the allowed target.
  let got = allowed_target(base, target_spacing + half_life)

  and {
    got > base * 2 * 99_999 / 100_000,
    got < base * 2 * 100_001 / 100_000,
  }
}

test loosening_is_monotone_in_elapsed_time() {
  // The property that makes a found hash safe to submit: waiting never makes
  // the target harder.
  let a = allowed_target(base, target_spacing)
  let b = allowed_target(base, target_spacing + 1)
  let c = allowed_target(base, target_spacing + half_life / 2)
  let d = allowed_target(base, target_spacing + half_life)

  a <= b && b < c && c < d
}

test half_a_half_life_overdue_is_sqrt_2() {
  let got = allowed_target(base, target_spacing + half_life / 2)

  // sqrt(2) = 1.41421356..., and this is where the cubic is least accurate.
  and {
    got > base * 141_400 / 100_000,
    got < base * 141_425 / 100_000,
  }
}

test a_long_stall_clamps_at_the_pow_limit() {
  allowed_target(base, half_life * 1_000_000) == pow_limit()
}

test the_shift_cutoff_never_changes_a_result() {
  // At max_shift whole half-lives the law gives at least base * 2^max_shift,
  // and base >= 1, so the early return only fires where the clamp would have
  // landed anyway.
  pow2(max_shift) > pow_limit()
}

test a_tight_base_follows_the_law_past_64_half_lives() {
  // 64 half-lives overdue, a base of 2^170 loosens to 2^234 --
  // not to the pow limit, which is what a cutoff at 64 returned.
  let stall = target_spacing + 64 * half_life

  and {
    allowed_target(pow2(170), stall) == pow2(234),
    next_base_target(pow2(170), stall) == pow2(234),
  }
}

test the_law_is_exact_right_up_to_the_pow_limit() {
  // From a base of 1, 254 half-lives is still short of the pow limit and 255
  // is past it.
  and {
    allowed_target(1, target_spacing + 254 * half_life) == pow2(254),
    allowed_target(1, target_spacing + 255 * half_life) == pow_limit(),
  }
}

test a_catch_up_after_a_long_stall_cannot_run_ahead() {
  // A stall of 64 half-lives past due, closed by one block, then instant
  // blocks. Each halves the base, so getting back to 2^170 takes 64 of them:
  // one per missed slot, not 84 as the cutoff at 64 gave (2^254 down to 2^170).
  let after_stall = next_base_target(pow2(170), target_spacing + 64 * half_life)
  let after_catch_up =
    list.foldl(list.range(1, 64), after_stall, fn(_, t) { next_base_target(t, 0) })

  after_catch_up == pow2(170)
}

test never_easier_than_the_pow_limit() {
  allowed_target(pow_limit(), target_spacing + half_life) == pow_limit()
}

// ## On a block

test an_on_time_block_leaves_the_base_alone() {
  next_base_target(base, target_spacing) == base
}

test a_fast_block_tightens_the_base() {
  // Found instantly: the base halves per half-life of earliness. At
  // half_life == target_spacing that is exactly one halving.
  let got = next_base_target(base, 0)

  and {
    got > base / 2 * 99_999 / 100_000,
    got < base / 2 * 100_001 / 100_000,
  }
}

test a_slow_block_loosens_the_base() {
  let got = next_base_target(base, target_spacing + half_life)

  and {
    got > base * 2 * 99_999 / 100_000,
    got < base * 2 * 100_001 / 100_000,
  }
}

test a_late_block_lands_on_the_target_it_was_mined_against() {
  // The continuity invariant: for any overdue interval, the base handed to the
  // next block equals the target this block had to meet.
  let late = target_spacing + half_life * 3 / 7

  next_base_target(base, late) == allowed_target(base, late)
}

test the_law_is_symmetric_about_the_target() {
  // Equal earliness and lateness move the base by reciprocal factors.
  let early = next_base_target(base, target_spacing - half_life)
  let late = next_base_target(base, target_spacing + half_life)

  and {
    // One half-life early halves the base; one half-life late doubles it.
    early * 2 > base * 99_999 / 100_000,
    early * 2 < base * 100_001 / 100_000,
    late > base * 2 * 99_999 / 100_000,
    late < base * 2 * 100_001 / 100_000,
    // So the two factors are reciprocal: equal and opposite deviations from
    // the target cancel, which is the unbiasedness the rule rests on.
    early * late > base * base * 99_999 / 100_000,
    early * late < base * base * 100_001 / 100_000,
  }
}

test a_surge_tightens_by_a_halving_per_instant_block() {
  // Eight blocks found instantly. At half_life == target_spacing each one
  // halves the base, so difficulty climbs 2^8 in eight blocks.
  let after_eight = list.foldl(
    list.range(1, 8),
    base,
    fn(_, t) { next_base_target(t, 0) },
  )

  // 2^8 = 256 times harder.
  and {
    after_eight * 256 > base * 99 / 100,
    after_eight * 256 < base * 101 / 100,
  }
}

test never_harder_than_one() {
  next_base_target(min_target, 0) == min_target
}
