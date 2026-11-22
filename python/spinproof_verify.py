#!/usr/bin/env python3
"""Independent verifier for SpinProof proofs (https://spinproof.app).

Repeats every check of a SpinProof proof page with nothing but the Python standard library:

    python spinproof_verify.py https://spinproof.app/r/abc23xyz
    python spinproof_verify.py abc23xyz              # a bare proof or draw code
    python spinproof_verify.py --file proof.json     # a saved copy of GET /api/spins/{code}
    python spinproof_verify.py --json abc23xyz       # machine-readable result

It needs no SpinProof code: it fetches the public proof record (or reads a file), recomputes the lock, the
draw and every winner itself, and compares a scheduled draw's randomness with the drand network.
Exit code: 0 when every check passed, 1 when a check failed, 2 when the proof could not be checked.
The maths is described in the README of this repository.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Callable, Optional

__version__ = '1.0.0'

SITE = 'https://spinproof.app'
USER_AGENT = f'spinproof-verifier/{__version__} (Python)'

# drand quicknet, the chain SpinProof's scheduled draws use: genesis time, period, chain hash, public relays.
QUICKNET_GENESIS = 1692803367
QUICKNET_PERIOD = 3
QUICKNET_CHAIN = '52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971'
DRAND_RELAYS = ('https://api.drand.sh', 'https://drand.cloudflare.com')

MAX_WEIGHT = 100
WEIGHT_PATTERN = re.compile(r'^(.*?\S)(?:\s+[xX]|\s*[×*])\s*([0-9]{1,3})\Z')
HEX64 = re.compile(r'^[0-9a-f]{64}\Z')
CODE = re.compile(r'^[a-z0-9]{6,16}\Z', re.IGNORECASE)


# ---------------------------------------------------------------------------------------------------------------
# The maths. Each function is one line of the README's "How a SpinProof draw works".
# ---------------------------------------------------------------------------------------------------------------

def sha256(text: str) -> str:
    """SHA-256 of a text (UTF-8), as 64 lowercase hex characters."""
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def fingerprint(entries: list[str]) -> str:
    """The list's fingerprint: SHA-256 of all entries joined with a line break, in wheel order."""
    return sha256('\n'.join(entries))


def lock_v1(secret: str) -> str:
    """Lock v1: SHA-256 of the secret (64 hex characters)."""
    return sha256(secret)


def statement(fp: str, entries_count: int, mode: str, draws: int, teams: Optional[int], is_weighted: bool,
              prizes_fp: Optional[str]) -> str:
    """Lock v2: the draw statement sealed by the lock (what is drawn, from which list, and how)."""
    return ':'.join(['spinproof-v2', fp, str(entries_count), mode, str(draws), str(teams or 0),
                     '1' if is_weighted else '0', prizes_fp or '-'])


def lock_v2(secret: str, stmt: str) -> str:
    """Lock v2: SHA-256 of secret ":" statement."""
    return sha256(f'{secret}:{stmt}')


def spin_seed(secret: str, client_seed: Optional[str]) -> str:
    """Lock v2: the draw seed, the server's secret mixed with the host browser's number ("" if none)."""
    return sha256(f'{secret}:{client_seed or ""}')


def draw_seed(secret: str, randomness: str) -> str:
    """Scheduled draws: the secret mixed with the drand round's randomness."""
    return sha256(f'{secret}:{randomness}')


def weighted(entry: str) -> tuple[str, int]:
    """An entry's label and weight: "Aisha *3", "Aisha x3" and "Aisha ×3" all count three times."""
    match = WEIGHT_PATTERN.match(entry)
    if match and 1 <= int(match.group(2)) <= MAX_WEIGHT:
        return match.group(1), int(match.group(2))
    return entry, 1


def pick_indexes(seed: str, fp: str, n: int, count: int, weights: Optional[list[int]] = None) -> list[int]:
    """Draw `count` entries (0-based positions in wheel order) without putting any back.

    Draw j: the first 12 hex characters of SHA-256(seed ":" fingerprint ":" j) as a number, modulo the entries
    still in the draw (or modulo their total weight, walking the remaining entries in order). The remainder
    picks the entry, which then leaves the draw.
    """
    remaining = list(range(n))
    picked = []
    for j in range(count):
        if not remaining:
            break
        value = int(sha256(f'{seed}:{fp}:{j}')[:12], 16)
        if weights:
            target = value % sum(weights[i] for i in remaining)
            for slot, index in enumerate(remaining):
                target -= weights[index]
                if target < 0:
                    break
        else:
            slot = value % len(remaining)
        picked.append(remaining.pop(slot))
    return picked


def deal_teams(order: list, count: int) -> list[list]:
    """Team mode: draw position p joins team (p mod count)."""
    teams: list[list] = [[] for _ in range(count)]
    for position, item in enumerate(order):
        teams[position % count].append(item)
    return teams


def first_round_after(timestamp: float) -> int:
    """The first drand quicknet round published after a moment (Unix seconds)."""
    return math.ceil((timestamp - QUICKNET_GENESIS) / QUICKNET_PERIOD) + 1


# ---------------------------------------------------------------------------------------------------------------
# The checks
# ---------------------------------------------------------------------------------------------------------------

@dataclass
class Check:
    status: str  # "ok", "fail" or "skip"
    text: str


class NotCheckable(Exception):
    """The proof cannot be checked (yet): not revealed, not found, or not a SpinProof record."""


Fetch = Callable[[str], dict]


def _iso_seconds(value: str) -> float:
    return datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()


def verify(proof: dict, fetch: Optional[Fetch] = None) -> list[Check]:
    """Every check of a revealed proof, in the order the proof page shows them.

    `fetch(url) -> dict` is used only to ask the drand network for a scheduled draw's round; pass None to skip
    that one comparison (the other drand checks still run offline).
    """
    if not proof.get('secret') or not proof.get('revealed_at'):
        raise NotCheckable('This spin is locked but not revealed yet. SpinProof reveals it automatically five '
                           'minutes after the lock; try again then.')

    checks: list[Check] = []

    def add(ok: bool, text: str) -> None:
        checks.append(Check('ok' if ok else 'fail', text))

    secret = proof['secret']
    fp = proof['fingerprint']
    n = int(proof['entries_count'])
    count = int(proof['winners_count'])
    mode = proof.get('mode') or 'pick'
    entries = proof.get('entries')
    winners = proof.get('winners') or []
    is_weighted = bool(proof.get('weighted'))
    v2 = int(proof.get('version') or 1) == 2

    # 1. The lock was published before the spin; only the real secret (and statement) give the same hash.
    if v2:
        stmt = statement(fp, n, mode, count, proof.get('teams_count'), is_weighted, proof.get('prizes_fingerprint'))
        add(stmt == proof.get('statement') and lock_v2(secret, stmt) == proof.get('commitment'),
            'Lock v2: SHA-256(secret:statement) is exactly the lock published before the spin, and the statement '
            f'matches this draw ({mode}, {count} drawn from {n}).')
    else:
        add(lock_v1(secret) == proof.get('commitment'),
            'Lock: SHA-256 of the revealed secret is exactly the lock published before the spin.')

    seed = secret
    if v2:
        client_seed = proof.get('client_seed') or ''
        if client_seed:
            add(bool(HEX64.match(client_seed)),
                f"Browser number: the host's browser added its own random number after the lock ({client_seed[:12]}…), "
                'so neither the server nor the host could choose the result alone.')
        else:
            checks.append(Check('skip', 'Browser number: none. Nobody revealed this spin, so SpinProof revealed it '
                                        'automatically and the draw used the secret with an empty number.'))
        seed = spin_seed(secret, client_seed)

    # 2. The list: its fingerprint was locked with the spin.
    if entries is not None:
        add(len(entries) == n and fingerprint(entries) == fp,
            f'Entries: the {n} entries are exactly the ones that were locked (their fingerprint matches).')

    # 3. Weighted draws: each entry counts as many times as its weight.
    draw_weights = None
    if is_weighted:
        published = proof.get('weights')
        draw_weights = [weighted(e)[1] for e in entries] if entries is not None else published
        add(isinstance(draw_weights, list) and len(draw_weights) == n
            and all(isinstance(w, int) and 1 <= w <= MAX_WEIGHT for w in draw_weights)
            and (not published or draw_weights == published),
            f'Weights: a weighted draw with {sum(draw_weights or [])} chances across {n} entries.')

    # 4. Scheduled draws: public randomness from drand, published only after entries closed.
    drand = proof.get('drand')
    if drand:
        add(hashlib.sha256(bytes.fromhex(drand['signature'])).hexdigest() == drand['randomness'],
            f"drand: the randomness is exactly the SHA-256 of round {drand['round']:,}'s signature.")
        first = first_round_after(_iso_seconds(drand['entries_closed_at']))
        add(first == drand['round'],
            f'drand: round {first:,} is the first one published after entries closed, so nobody knew it in advance.')
        checks.append(compare_with_drand(drand, fetch))
        seed = draw_seed(secret, drand['randomness'])

    # 5. The draw itself.
    indexes = pick_indexes(seed, fp, n, count, draw_weights)
    positions_ok = len(indexes) == len(winners) and all(
        isinstance(w, dict) and w.get('index') == i for w, i in zip(winners, indexes))
    names_ok = entries is None or all(
        0 <= w['index'] < n and (weighted(entries[w['index']])[0] if is_weighted else entries[w['index']]) == w['name']
        for w in winners)
    if mode == 'teams':
        what = f'the draw order of all {n} entries'
    elif mode == 'eliminate':
        what = f"the knockout order of all {n} entries; {winners[-1]['name'] if winners else '?'} is left standing"
    else:
        what = ', '.join(f"{w.get('name')} (entry {w.get('index', -1) + 1})" for w in winners)
    add(positions_ok and names_ok, f'Draw: the {"seed" if v2 or drand else "secret"} gives exactly {what}.')

    # 6. Teams follow from the draw order.
    if mode == 'teams':
        teams_count = int(proof.get('teams_count') or 0)
        dealt = [[m['index'] for m in team] for team in deal_teams(winners, teams_count)] if teams_count else []
        shown = [[m.get('index') for m in team] for team in (proof.get('teams') or [])]
        add(bool(dealt) and dealt == shown,
            f'Teams: the {teams_count} teams follow from the draw order (draw j joins team j mod {teams_count} + 1).')

    # 7. Linked wheels: wheel 2 is drawn with the same seed and its own fingerprint, one draw per winner.
    if mode == 'linked':
        prizes = proof.get('prizes') or []
        prize_winners = proof.get('prize_winners') or []
        prizes_fp = proof.get('prizes_fingerprint')
        add(fingerprint(prizes) == prizes_fp, f"Wheel 2: its {len(prizes)} items are exactly the ones that were locked.")
        drawn = pick_indexes(seed, prizes_fp or '', len(prizes), count)
        add(len(drawn) == len(prize_winners) and all(
            p.get('index') == i and prizes[i] == p.get('name') for p, i in zip(prize_winners, drawn)),
            'Wheel 2: the same seed gives each winner exactly this item: '
            + ', '.join(f"{w.get('name')} → {p.get('name')}" for w, p in zip(winners, prize_winners)) + '.')

    if entries is None:
        checks.append(Check('skip', 'Entries: the host shortened the names on the public proof, so the list itself '
                                    'cannot be checked here. The lock and the winning positions still are.'))
    return checks


def compare_with_drand(drand: dict, fetch: Optional[Fetch]) -> Check:
    """Asks the drand network itself for the round, so the randomness is not taken on SpinProof's word."""
    if fetch is None:
        return Check('skip', 'drand: not compared with the drand network (offline). Open '
                             f"{DRAND_RELAYS[0]}/{drand.get('chain', QUICKNET_CHAIN)}/public/{drand['round']} to compare.")
    for relay in DRAND_RELAYS:
        try:
            beacon = fetch(f"{relay}/{drand.get('chain', QUICKNET_CHAIN)}/public/{drand['round']}")
        except Exception:  # noqa: BLE001 - try the next relay
            continue
        host = urllib.parse.urlparse(relay).hostname
        ok = beacon.get('randomness') == drand['randomness'] and beacon.get('signature') == drand['signature']
        return Check('ok' if ok else 'fail',
                     f"drand: the randomness matches round {drand['round']:,} as published by the drand network ({host}).")
    return Check('skip', 'drand: the drand network could not be reached to compare the round.')


def passed(checks: list[Check]) -> bool:
    real = [c for c in checks if c.status != 'skip']
    return bool(real) and all(c.status == 'ok' for c in real)


def result_line(proof: dict) -> str:
    winners = proof.get('winners') or []
    mode = proof.get('mode')
    if mode == 'teams':
        return '; '.join(f"Team {i + 1}: " + ', '.join(m['name'] for m in team)
                         for i, team in enumerate(proof.get('teams') or []))
    if mode == 'eliminate':
        return f"{winners[-1]['name']} was left standing" if winners else ''
    if mode == 'linked':
        return ', '.join(f"{w['name']} → {p['name']}" for w, p in zip(winners, proof.get('prize_winners') or []))
    return ', '.join(w['name'] for w in winners)


# ---------------------------------------------------------------------------------------------------------------
# Fetching a proof
# ---------------------------------------------------------------------------------------------------------------

def parse_input(text: str, site: str = SITE) -> tuple[str, str]:
    """A proof link (/r/code), a scheduled draw link (/d/code) or a bare code -> (kind, code)."""
    value = text.strip()
    if CODE.match(value):
        return 'any', value.lower()
    url = urllib.parse.urlparse(value if re.match(r'^[a-z][a-z0-9+.-]*://', value, re.I) else f'https://{value}')
    host = urllib.parse.urlparse(site).hostname
    if url.hostname not in (host, f'www.{host}'):
        raise NotCheckable(f'Not a {host} link. Paste a proof link like {site}/r/abc23xyz or its code.')
    match = re.match(r'^/(r|d)/([a-z0-9]{6,16})/?$', url.path, re.I)
    if not match:
        raise NotCheckable(f'Not a proof link. Proof links look like {site}/r/abc23xyz.')
    return ('spin' if match.group(1).lower() == 'r' else 'draw'), match.group(2).lower()


def http_json(url: str, timeout: float = 15) -> dict:
    request = urllib.request.Request(url, headers={'Accept': 'application/json', 'User-Agent': USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


def load_proof(kind: str, code: str, site: str = SITE, fetch: Fetch = http_json) -> dict:
    """The proof behind a code: GET /api/spins/{code}, or a scheduled draw's result from GET /api/draws/{code}."""
    if kind != 'draw':
        try:
            return fetch(f'{site}/api/spins/{code}')
        except urllib.error.HTTPError as error:
            if error.code != 404 or kind == 'spin':
                raise NotCheckable(f'{site} answered {error.code} for this proof.') from error
    try:
        draw = fetch(f'{site}/api/draws/{code}')['draw']
    except urllib.error.HTTPError as error:
        raise NotCheckable('No proof or scheduled draw has this code.' if error.code == 404
                           else f'{site} answered {error.code} for this draw.') from error
    if not draw.get('result'):
        raise NotCheckable(f"This scheduled draw has not happened yet (draw time {draw.get('draw_at')}).")
    return draw['result']


# ---------------------------------------------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------------------------------------------

def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description='Check a SpinProof proof without any SpinProof code.')
    parser.add_argument('proof', nargs='?', help='proof link (https://spinproof.app/r/…), draw link (/d/…) or code')
    parser.add_argument('--file', help='read the proof JSON from a file ("-" for standard input) instead of the site')
    parser.add_argument('--json', action='store_true', help='print the result as JSON')
    parser.add_argument('--offline', action='store_true', help='do not contact the drand network')
    parser.add_argument('--site', default=SITE, help=argparse.SUPPRESS)
    parser.add_argument('--version', action='version', version=f'spinproof-verifier {__version__}')
    args = parser.parse_args(argv)
    if bool(args.proof) == bool(args.file):
        parser.error('give a proof link or code, or --file')

    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')  # type: ignore[attr-defined]
    except (AttributeError, ValueError):
        pass

    try:
        if args.file:
            source = sys.stdin if args.file == '-' else open(args.file, encoding='utf-8')
            with source:
                proof = json.load(source)
            if isinstance(proof.get('draw'), dict):  # a saved copy of GET /api/draws/{code}
                if not proof['draw'].get('result'):
                    raise NotCheckable('This scheduled draw has not happened yet.')
                proof = proof['draw']['result']
        else:
            proof = load_proof(*parse_input(args.proof, args.site), site=args.site)
        checks = verify(proof, fetch=None if args.offline else http_json)
    except NotCheckable as error:
        return _fail(args.json, str(error))
    except (urllib.error.URLError, OSError, ValueError, KeyError, TypeError) as error:
        return _fail(args.json, f'Could not check this proof: {error}')

    ok = passed(checks)
    if args.json:
        print(json.dumps({'passed': ok, 'id': proof.get('id'), 'proof_url': proof.get('proof_url'),
                          'version': int(proof.get('version') or 1), 'result': result_line(proof),
                          'checks': [asdict(c) for c in checks]}, ensure_ascii=False, indent=2))
    else:
        marks = {'ok': '✓', 'fail': '✗', 'skip': '–'}
        method = 'scheduled draw with drand' if proof.get('drand') else f"Lock v{int(proof.get('version') or 1)}"
        print(f"SpinProof verifier {__version__}")
        print(f"Proof   {proof.get('proof_url') or proof.get('id')}")
        print(f"Title   {proof.get('title')} · spin {proof.get('spin_number')} · {method}")
        print(f"Result  {result_line(proof)}\n")
        for check in checks:
            print(f'  {marks[check.status]} {check.text}')
        real = sum(c.status != 'skip' for c in checks)
        print('\nPASSED: all {} checks passed. Nothing was changed after the lock.'.format(real) if ok
              else '\nFAILED: at least one check did not pass. This result does not match its lock.')
    return 0 if ok else 1


def _fail(as_json: bool, message: str) -> int:
    if as_json:
        print(json.dumps({'passed': False, 'error': message}, ensure_ascii=False))
    else:
        print(message, file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main())
