# SpinProof Verifier

[![Tests](https://github.com/gojisolution/spinproof-verifier/actions/workflows/test.yml/badge.svg)](https://github.com/gojisolution/spinproof-verifier/actions/workflows/test.yml)
[![MIT licence](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)
![No dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)

Independent, open-source checker for spin proofs from [SpinProof](https://spinproof.app), the provably fair
wheel spinner. Give it a proof link and it repeats every step of the draw itself: the lock published before the
spin, the browser's random number, the seed and each winner. It uses no SpinProof code, only SHA-256.

**Check one now in your browser:** https://gojisolution.github.io/spinproof-verifier/ · or open it with an
[example proof](https://gojisolution.github.io/spinproof-verifier/?p=cdtupn9m) already filled in (its
[proof page on SpinProof](https://spinproof.app/r/cdtupn9m)).

Every SpinProof proof page already runs these checks in the visitor's browser. That code, though, is served by
SpinProof itself. This repository exists so that you do not have to trust it: the whole verifier is one short
file in Python and one in JavaScript, with no dependencies, that you can read in a few minutes and run anywhere.

- [Quick start](#quick-start)
- [What is checked](#what-is-checked)
- [How a SpinProof draw works](#how-a-spinproof-draw-works)
- [What a proof can and cannot show](#what-a-proof-can-and-cannot-show)
- [The proof record](#the-proof-record)
- [Tests and test vectors](#tests-and-test-vectors)

## Quick start

### In the browser

Open https://gojisolution.github.io/spinproof-verifier/, paste a proof link and press **Check**. A link like
`https://gojisolution.github.io/spinproof-verifier/?p=abc23xyz` opens with that proof already checked. The page
runs [`js/spinproof-verify.mjs`](js/spinproof-verify.mjs) from this repository and talks only to the SpinProof
API and, for scheduled draws, the drand network.

### Python 3.9+

```sh
python python/spinproof_verify.py https://spinproof.app/r/abc23xyz
python python/spinproof_verify.py abc23xyz                  # the code alone
python python/spinproof_verify.py https://spinproof.app/d/fb22xr68   # a scheduled draw
python python/spinproof_verify.py --file proof.json         # a saved record, nothing fetched
python python/spinproof_verify.py --json abc23xyz           # machine-readable
```

```text
$ python python/spinproof_verify.py https://spinproof.app/r/cdtupn9m
SpinProof verifier 1.0.0
Proof   https://spinproof.app/r/cdtupn9m
Title   Verifier example · spin 1 · Lock v2
Result  Farah, Gabriel

  ✓ Lock v2: SHA-256(secret:statement) is exactly the lock published before the spin, and the statement matches this draw (pick, 2 drawn from 8).
  ✓ Browser number: the host's browser added its own random number after the lock (658506bd9112…), so neither the server nor the host could choose the result alone.
  ✓ Entries: the 8 entries are exactly the ones that were locked (their fingerprint matches).
  ✓ Draw: the seed gives exactly Farah (entry 6), Gabriel (entry 7).

PASSED: all 4 checks passed. Nothing was changed after the lock.
```

The exit code is `0` when every check passed, `1` when a check failed and `2` when the proof could not be checked
(not found, not revealed yet, no network). Add `--offline` to skip asking the drand network.

### Node.js 18+

```sh
node js/spinproof-verify.mjs https://spinproof.app/r/abc23xyz
node js/spinproof-verify.mjs --file proof.json --json
```

### As a library

```js
import { loadProof, parseInput, verify, passed } from './js/spinproof-verify.mjs';

const proof = await loadProof(...parseInput('https://spinproof.app/r/abc23xyz'));
const checks = await verify(proof);          // [{ status: 'ok' | 'fail' | 'skip', text }]
console.log(passed(checks));
```

```python
import spinproof_verify as sv

proof = sv.load_proof(*sv.parse_input('abc23xyz'))
checks = sv.verify(proof, fetch=sv.http_json)
print(sv.passed(checks))
```

Every step of the maths is also exported on its own (`fingerprint`, `statement`, `lock_v2` / `lockV2`,
`spin_seed` / `spinSeed`, `pick_indexes` / `pickIndexes`, …).

## What is checked

| Check | What it proves |
|---|---|
| Lock | The revealed secret (and, in Lock v2, the draw statement) hashes to exactly the lock published before the spin. The result cannot have been swapped afterwards. |
| Draw statement (v2) | The mode, the number of draws, teams, the weights flag and wheel 2 were sealed in the lock, so a different setting cannot be passed off later. |
| Browser number (v2) | The host's browser added its own random number after receiving the lock. |
| Entries | The list hashes to the fingerprint locked with the spin. Skipped when the host chose to shorten names on the public proof. |
| Weights | A weighted draw used exactly the published weights. |
| drand (scheduled draws) | The randomness is the SHA-256 of the round's signature, the round is the first published after entries closed, and two public drand relays return the same round. |
| Draw | Recomputing the draw gives exactly the published winners, in order. |
| Teams | The teams follow from the draw order. |
| Wheel 2 (linked wheels) | Wheel 2's list is the locked one, and the same seed gives each winner exactly the item shown. |

## How a SpinProof draw works

Everything below uses SHA-256 written as 64 lowercase hex characters. `:` is a literal colon.

**Fingerprint.** `fingerprint = SHA-256(entries joined with "\n")`, in wheel order, exactly as entered (a weighted
entry keeps its `*3`).

**Secret.** 32 random bytes from the server's cryptographic generator, as 64 hex characters.

### Lock v2 (spins locked since November 2026, `"version": 2`)

```
statement = "spinproof-v2:" fingerprint ":" entries ":" mode ":" draws ":" teams ":" weighted ":" wheel2_fingerprint
lock      = SHA-256(secret ":" statement)
seed      = SHA-256(secret ":" browser_number)
```

- `mode` is `pick`, `teams`, `eliminate` or `linked`; `draws` is how many entries are drawn (everyone in team and
  elimination mode); `teams` is the number of teams, or `0`; `weighted` is `1` or `0`; `wheel2_fingerprint` is the
  fingerprint of wheel 2's list, or `-`.
- When the host presses Spin, the server fixes the entries and the secret and returns **only the lock**.
- Only then does the host's browser send `browser_number`, 32 random bytes as 64 hex characters. The server could
  not aim its secret at a winner because it did not know the number; the browser could not aim the number because
  it did not know the secret.
- If nobody reveals a spin, SpinProof reveals it automatically five minutes after the lock, with an empty browser
  number (`seed = SHA-256(secret ":")`). The proof says so.

### Lock v1 (older spins, `"version": 1`)

```
lock = SHA-256(secret)
seed = secret
```

### Scheduled draws

The lock is published when the draw is scheduled. Entries can change until the draw time and never after. The
draw then uses the [drand](https://drand.love) quicknet round published right after entries closed:

```
round = ceil((entries_closed_at - 1692803367) / 3) + 1
seed  = SHA-256(secret ":" randomness)        where randomness = SHA-256(signature bytes)
```

drand is run by an independent group of organisations, and nobody can know a round before it is published.

### Picking the winners

```
for j = 0, 1, 2, …:
    value = first 12 hex characters of SHA-256(seed ":" fingerprint ":" j), as an integer
    slot  = value mod (number of entries still in the draw)
    the entry at that slot among the remaining ones (in wheel order) is draw j, and leaves the draw
```

- **Weighted draws** (`Aisha *3`, `Aisha x3`, `Aisha ×3`): `value mod (total weight still in the draw)`, then walk
  the remaining entries in order, subtracting each weight, until the running value drops below zero.
- **Teams:** everyone is drawn; draw `j` joins team `j mod teams` (+1 when counting from 1).
- **Elimination:** everyone is drawn; draw `j` is out in round `j + 1`, and the last one drawn is left standing.
- **Linked wheels:** wheel 2 is drawn the same way with the same seed and its own fingerprint,
  `SHA-256(seed ":" wheel2_fingerprint ":" j)`, one draw per winner; winner `j` gets wheel 2's draw `j`.

## What a proof can and cannot show

- **It shows** that the result was fixed before the spin and not changed afterwards, that it follows from the
  published numbers, and (Lock v2 and scheduled draws) that the server alone could not choose it.
- **It also shows re-spins.** Every spin of a wheel is numbered, and the proof page on spinproof.app lists every
  spin of the same wheel, so "spin 1 of 1" means there was no quiet second try.
- **It cannot show** that the host entered everyone who should have been in the draw. Ask the host for the list.
  When names are shortened on the public proof, the list cannot be checked against the fingerprint, though the
  lock and the winning positions still can.
- **drand signatures** are compared with two public drand relays, not verified with BLS cryptography here. To check
  the signature itself, use drand's own tools with the quicknet chain hash
  `52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971`.
- **A pasted or saved record** proves only what is in it. Compare it with the live proof page, or let the verifier
  fetch it from spinproof.app.

## The proof record

The verifier reads the public record at `GET https://spinproof.app/api/spins/{code}` (a scheduled draw's result is
`draw.result` in `GET https://spinproof.app/api/draws/{code}`). The fields it uses:

| Field | Meaning |
|---|---|
| `version` | `1` or `2` (Lock v1 or Lock v2) |
| `commitment` | the lock published before the spin |
| `statement` | Lock v2 draw statement |
| `secret` | the server's secret, published after the reveal |
| `client_seed` | Lock v2 browser number (`""` when revealed automatically) |
| `fingerprint`, `entries_count`, `entries` | the list's fingerprint, its size, and the names (or `null` when shortened) |
| `mode`, `winners_count`, `teams_count`, `teams` | how the draw was made, and the teams it produced |
| `weighted`, `weights` | weighted draw and each entry's weight (public even when names are shortened) |
| `prizes`, `prizes_fingerprint`, `prize_winners` | linked wheels: wheel 2's list, fingerprint and draws |
| `drand` | scheduled draws: `round`, `randomness`, `signature`, `chain`, `entries_closed_at` |
| `winners` | the draws in order, each `{index, name}` (0-based position in wheel order) |
| `locked_at`, `revealed_at` | when the spin was locked and revealed |

## Tests and test vectors

```sh
python -m unittest discover -s tests -p "test_*.py"
node --test tests/test_js.mjs
```

The tests run offline. [`fixtures/vectors.json`](fixtures/vectors.json) holds known answers shared with
SpinProof's own test suite, so any new implementation can be checked against them. The `fixtures/v*.json` files
are complete proof records in every mode (Lock v1, Lock v2, weighted, teams, elimination, linked wheels, an
automatic reveal and a scheduled draw on a real drand round). They were made on a test copy of SpinProof with
made-up names and do not exist on spinproof.app. The tests also change each fixture (a winner, the secret, the lock,
the mode, the browser number, the teams, wheel 2, the drand round) and expect every change to be caught.

## Reporting a problem

Open an [issue](https://github.com/gojisolution/spinproof-verifier/issues). If you think you have found a way to
fake a result that these checks would accept, please use **Report a vulnerability** on the
[Security tab](https://github.com/gojisolution/spinproof-verifier/security) instead, so it can be fixed first.

## Licence

[MIT](LICENSE). Use it, copy it, port it to other languages.
