// Independent verifier for SpinProof proofs (https://spinproof.app), for browsers and Node.js 18+.
// No dependencies. It repeats every check of a SpinProof proof page with the Web Crypto API.
//
//   node js/spinproof-verify.mjs https://spinproof.app/r/abc23xyz
//   node js/spinproof-verify.mjs --file proof.json --json
//
//   import { loadProof, parseInput, verify, passed } from './spinproof-verify.mjs';
//   const checks = await verify(await loadProof(...parseInput('abc23xyz')));
//
// Exit code (command line): 0 when every check passed, 1 when a check failed, 2 when the proof could not be checked.
// The maths is described in the README of this repository; python/spinproof_verify.py does exactly the same.

export const VERSION = '1.0.0';
export const SITE = 'https://spinproof.app';

// drand quicknet, the chain SpinProof's scheduled draws use.
export const QUICKNET_GENESIS = 1692803367;
export const QUICKNET_PERIOD = 3;
export const QUICKNET_CHAIN = '52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971';
export const DRAND_RELAYS = ['https://api.drand.sh', 'https://drand.cloudflare.com'];

const MAX_WEIGHT = 100;
const WEIGHT_PATTERN = /^(.*?\S)(?:\s+[xX]|\s*[×*])\s*([0-9]{1,3})$/u;
const HEX64 = /^[0-9a-f]{64}$/;
const CODE = /^[a-z0-9]{6,16}$/i;

const subtle = globalThis.crypto?.subtle ?? (await import('node:crypto')).webcrypto.subtle;
const encoder = new TextEncoder();
const hex = (buffer) => Array.from(new Uint8Array(buffer), (b) => b.toString(16).padStart(2, '0')).join('');

// ---- The maths. Each function is one line of the README's "How a SpinProof draw works". ------------------------

/** SHA-256 of a text (UTF-8), as 64 lowercase hex characters. */
export const sha256 = async (text) => hex(await subtle.digest('SHA-256', encoder.encode(text)));

/** SHA-256 of bytes written as hex (drand: randomness = SHA-256 of the signature bytes). */
export const sha256Bytes = async (hexText) =>
    hex(await subtle.digest('SHA-256', new Uint8Array((hexText.match(/../g) || []).map((b) => parseInt(b, 16)))));

/** The list's fingerprint: SHA-256 of all entries joined with a line break, in wheel order. */
export const fingerprint = (entries) => sha256(entries.join('\n'));

/** Lock v1: SHA-256 of the secret. */
export const lockV1 = (secret) => sha256(secret);

/** Lock v2: the draw statement sealed by the lock (what is drawn, from which list, and how). */
export const statement = (fp, entriesCount, mode, draws, teams, isWeighted, prizesFp) =>
    ['spinproof-v2', fp, entriesCount, mode, draws, teams || 0, isWeighted ? 1 : 0, prizesFp || '-'].join(':');

/** Lock v2: SHA-256 of secret ":" statement. */
export const lockV2 = (secret, stmt) => sha256(`${secret}:${stmt}`);

/** Lock v2: the draw seed, the server's secret mixed with the host browser's number ("" if none). */
export const spinSeed = (secret, clientSeed) => sha256(`${secret}:${clientSeed || ''}`);

/** Scheduled draws: the secret mixed with the drand round's randomness. */
export const drawSeed = (secret, randomness) => sha256(`${secret}:${randomness}`);

/** An entry's label and weight: "Aisha *3", "Aisha x3" and "Aisha ×3" all count three times. */
export function weighted(entry) {
    const match = WEIGHT_PATTERN.exec(entry);
    const weight = match ? parseInt(match[2], 10) : 0;
    return weight >= 1 && weight <= MAX_WEIGHT ? [match[1], weight] : [entry, 1];
}

/**
 * Draw `count` entries (0-based positions in wheel order) without putting any back. Draw j: the first 12 hex
 * characters of SHA-256(seed ":" fingerprint ":" j) as a number (48 bits, exact in a JS number), modulo the
 * entries still in the draw, or modulo their total weight while walking the remaining entries in order.
 */
export async function pickIndexes(seed, fp, n, count, weights = null) {
    const remaining = Array.from({ length: n }, (_, i) => i);
    const picked = [];
    for (let j = 0; j < count && remaining.length; j++) {
        const value = parseInt((await sha256(`${seed}:${fp}:${j}`)).slice(0, 12), 16);
        let slot;
        if (weights) {
            let target = value % remaining.reduce((sum, i) => sum + weights[i], 0);
            for (slot = 0; slot < remaining.length; slot++) {
                target -= weights[remaining[slot]];
                if (target < 0) break;
            }
        } else {
            slot = value % remaining.length;
        }
        picked.push(remaining.splice(slot, 1)[0]);
    }
    return picked;
}

/** Team mode: draw position p joins team (p mod count). */
export function dealTeams(order, count) {
    const teams = Array.from({ length: count }, () => []);
    order.forEach((item, position) => teams[position % count].push(item));
    return teams;
}

/** The first drand quicknet round published after a moment (Unix seconds). */
export const firstRoundAfter = (seconds) => Math.ceil((seconds - QUICKNET_GENESIS) / QUICKNET_PERIOD) + 1;

// ---- The checks ------------------------------------------------------------------------------------------------

/** The proof cannot be checked (yet): not revealed, not found, or not a SpinProof record. */
export class NotCheckable extends Error {}

const ok = (condition, text) => ({ status: condition ? 'ok' : 'fail', text });
const skip = (text) => ({ status: 'skip', text });
const num = (value) => Number(value).toLocaleString('en-US');

/**
 * Every check of a revealed proof (the JSON of GET /api/spins/{code}), in the order the proof page shows them.
 * Returns [{status: 'ok' | 'fail' | 'skip', text}]. `fetchJson(url)` is used only to ask the drand network for a
 * scheduled draw's round; pass null to skip that comparison (the other drand checks still run).
 */
export async function verify(proof, { fetchJson = defaultFetchJson } = {}) {
    if (!proof?.secret || !proof?.revealed_at) {
        throw new NotCheckable('This spin is locked but not revealed yet. SpinProof reveals it automatically five minutes after the lock; try again then.');
    }
    const checks = [];
    const { secret, fingerprint: fp, entries = null, drand = null } = proof;
    const n = Number(proof.entries_count);
    const count = Number(proof.winners_count);
    const mode = proof.mode || 'pick';
    const winners = proof.winners || [];
    const isWeighted = !!proof.weighted;
    const v2 = Number(proof.version || 1) === 2;

    // 1. The lock was published before the spin; only the real secret (and statement) give the same hash.
    if (v2) {
        const stmt = statement(fp, n, mode, count, proof.teams_count, isWeighted, proof.prizes_fingerprint);
        checks.push(ok(stmt === proof.statement && (await lockV2(secret, stmt)) === proof.commitment,
            `Lock v2: SHA-256(secret:statement) is exactly the lock published before the spin, and the statement matches this draw (${mode}, ${count} drawn from ${n}).`));
    } else {
        checks.push(ok((await lockV1(secret)) === proof.commitment, 'Lock: SHA-256 of the revealed secret is exactly the lock published before the spin.'));
    }

    let seed = secret;
    if (v2) {
        const clientSeed = proof.client_seed || '';
        checks.push(clientSeed
            ? ok(HEX64.test(clientSeed), `Browser number: the host's browser added its own random number after the lock (${clientSeed.slice(0, 12)}…), so neither the server nor the host could choose the result alone.`)
            : skip('Browser number: none. Nobody revealed this spin, so SpinProof revealed it automatically and the draw used the secret with an empty number.'));
        seed = await spinSeed(secret, clientSeed);
    }

    // 2. The list: its fingerprint was locked with the spin.
    if (entries) {
        checks.push(ok(entries.length === n && (await fingerprint(entries)) === fp, `Entries: the ${n} entries are exactly the ones that were locked (their fingerprint matches).`));
    }

    // 3. Weighted draws: each entry counts as many times as its weight.
    let drawWeights = null;
    if (isWeighted) {
        const published = proof.weights;
        drawWeights = entries ? entries.map((e) => weighted(e)[1]) : published;
        const valid = Array.isArray(drawWeights) && drawWeights.length === n
            && drawWeights.every((w) => Number.isInteger(w) && w >= 1 && w <= MAX_WEIGHT)
            && (!published || drawWeights.every((w, i) => w === published[i]));
        checks.push(ok(valid, `Weights: a weighted draw with ${(drawWeights || []).reduce((a, b) => a + b, 0)} chances across ${n} entries.`));
    }

    // 4. Scheduled draws: public randomness from drand, published only after entries closed.
    if (drand) {
        checks.push(ok((await sha256Bytes(drand.signature)) === drand.randomness, `drand: the randomness is exactly the SHA-256 of round ${num(drand.round)}'s signature.`));
        const first = firstRoundAfter(Date.parse(drand.entries_closed_at) / 1000);
        checks.push(ok(first === drand.round, `drand: round ${num(first)} is the first one published after entries closed, so nobody knew it in advance.`));
        checks.push(await compareWithDrand(drand, fetchJson));
        seed = await drawSeed(secret, drand.randomness);
    }

    // 5. The draw itself.
    const indexes = await pickIndexes(seed, fp, n, count, drawWeights);
    const positionsOk = indexes.length === winners.length && indexes.every((index, i) => winners[i]?.index === index);
    const label = (entry) => (isWeighted ? weighted(entry)[0] : entry);
    const namesOk = !entries || winners.every((w) => w.index >= 0 && w.index < n && label(entries[w.index]) === w.name);
    const what = mode === 'teams' ? `the draw order of all ${n} entries`
        : mode === 'eliminate' ? `the knockout order of all ${n} entries; ${winners.at(-1)?.name ?? '?'} is left standing`
            : winners.map((w) => `${w.name} (entry ${w.index + 1})`).join(', ');
    checks.push(ok(positionsOk && namesOk, `Draw: the ${v2 || drand ? 'seed' : 'secret'} gives exactly ${what}.`));

    // 6. Teams follow from the draw order.
    if (mode === 'teams') {
        const teamsCount = Number(proof.teams_count || 0);
        const dealt = teamsCount ? JSON.stringify(dealTeams(winners, teamsCount).map((team) => team.map((m) => m.index))) : '';
        const shown = JSON.stringify((proof.teams || []).map((team) => team.map((m) => m.index)));
        checks.push(ok(!!dealt && dealt === shown, `Teams: the ${teamsCount} teams follow from the draw order (draw j joins team j mod ${teamsCount} + 1).`));
    }

    // 7. Linked wheels: wheel 2 is drawn with the same seed and its own fingerprint, one draw per winner.
    if (mode === 'linked') {
        const prizes = proof.prizes || [];
        const prizeWinners = proof.prize_winners || [];
        checks.push(ok((await fingerprint(prizes)) === proof.prizes_fingerprint, `Wheel 2: its ${prizes.length} items are exactly the ones that were locked.`));
        const drawn = await pickIndexes(seed, proof.prizes_fingerprint || '', prizes.length, count);
        const pairs = winners.map((w, i) => `${w.name} → ${prizeWinners[i]?.name}`).join(', ');
        checks.push(ok(drawn.length === prizeWinners.length && drawn.every((index, i) => prizeWinners[i].index === index && prizes[index] === prizeWinners[i].name),
            `Wheel 2: the same seed gives each winner exactly this item: ${pairs}.`));
    }

    if (!entries) {
        checks.push(skip('Entries: the host shortened the names on the public proof, so the list itself cannot be checked here. The lock and the winning positions still are.'));
    }
    return checks;
}

/** Asks the drand network itself for the round, so the randomness is not taken on SpinProof's word. */
export async function compareWithDrand(drand, fetchJson = defaultFetchJson) {
    const path = `${drand.chain || QUICKNET_CHAIN}/public/${drand.round}`;
    if (!fetchJson) return skip(`drand: not compared with the drand network (offline). Open ${DRAND_RELAYS[0]}/${path} to compare.`);
    for (const relay of DRAND_RELAYS) {
        try {
            const beacon = await fetchJson(`${relay}/${path}`);
            return ok(beacon.randomness === drand.randomness && beacon.signature === drand.signature,
                `drand: the randomness matches round ${num(drand.round)} as published by the drand network (${new URL(relay).host}).`);
        } catch {
            // Try the next relay.
        }
    }
    return skip('drand: the drand network could not be reached to compare the round.');
}

export const passed = (checks) => {
    const real = checks.filter((c) => c.status !== 'skip');
    return real.length > 0 && real.every((c) => c.status === 'ok');
};

export function resultLine(proof) {
    const winners = proof.winners || [];
    if (proof.mode === 'teams') return (proof.teams || []).map((team, i) => `Team ${i + 1}: ${team.map((m) => m.name).join(', ')}`).join('; ');
    if (proof.mode === 'eliminate') return winners.length ? `${winners.at(-1).name} was left standing` : '';
    if (proof.mode === 'linked') return winners.map((w, i) => `${w.name} → ${proof.prize_winners?.[i]?.name}`).join(', ');
    return winners.map((w) => w.name).join(', ');
}

// ---- Fetching a proof ------------------------------------------------------------------------------------------

/** A proof link (/r/code), a scheduled draw link (/d/code) or a bare code -> [kind, code]. */
export function parseInput(text, site = SITE) {
    const value = String(text || '').trim();
    if (CODE.test(value)) return ['any', value.toLowerCase()];
    const host = new URL(site).host;
    let url;
    try {
        url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : `https://${value}`);
    } catch {
        throw new NotCheckable(`Not a proof link. Proof links look like ${site}/r/abc23xyz.`);
    }
    if (url.host !== host && url.host !== `www.${host}`) throw new NotCheckable(`Not a ${host} link. Paste a proof link like ${site}/r/abc23xyz or its code.`);
    const match = url.pathname.match(/^\/(r|d)\/([a-z0-9]{6,16})\/?$/i);
    if (!match) throw new NotCheckable(`Not a proof link. Proof links look like ${site}/r/abc23xyz.`);
    return [match[1].toLowerCase() === 'r' ? 'spin' : 'draw', match[2].toLowerCase()];
}

export class HttpError extends Error {
    constructor(status, url) {
        super(`${url} answered ${status}`);
        this.status = status;
    }
}

export async function defaultFetchJson(url) {
    const response = await fetch(url, { headers: { Accept: 'application/json' } });
    if (!response.ok) throw new HttpError(response.status, url);
    return response.json();
}

/** The proof behind a code: GET /api/spins/{code}, or a scheduled draw's result from GET /api/draws/{code}. */
export async function loadProof(kind, code, { site = SITE, fetchJson = defaultFetchJson } = {}) {
    if (kind !== 'draw') {
        try {
            return await fetchJson(`${site}/api/spins/${code}`);
        } catch (error) {
            if (error.status !== 404 || kind === 'spin') throw new NotCheckable(error.status ? `${site} answered ${error.status} for this proof.` : `Could not reach ${site}: ${error.message}`);
        }
    }
    let draw;
    try {
        ({ draw } = await fetchJson(`${site}/api/draws/${code}`));
    } catch (error) {
        throw new NotCheckable(error.status === 404 ? 'No proof or scheduled draw has this code.' : `${site} answered ${error.status || error.message} for this draw.`);
    }
    if (!draw?.result) throw new NotCheckable(`This scheduled draw has not happened yet (draw time ${draw?.draw_at}).`);
    return draw.result;
}

// ---- Command line (Node.js) ------------------------------------------------------------------------------------

async function main(argv) {
    const args = argv.filter((a) => !a.startsWith('--'));
    const flag = (name) => argv.includes(`--${name}`);
    const fileAt = argv.indexOf('--file');
    const file = fileAt >= 0 ? argv[fileAt + 1] : null;
    const input = args.find((a) => a !== file);
    if (flag('help') || (!input && !file)) {
        console.log('Usage: node spinproof-verify.mjs <proof link or code> [--json] [--offline]\n       node spinproof-verify.mjs --file proof.json [--json] [--offline]');
        return flag('help') ? 0 : 2;
    }
    const asJson = flag('json');
    let proof;
    let checks;
    try {
        if (file) {
            const { readFile } = await import('node:fs/promises');
            proof = JSON.parse(await readFile(file, 'utf8'));
            if (proof.draw) {
                if (!proof.draw.result) throw new NotCheckable('This scheduled draw has not happened yet.');
                proof = proof.draw.result;
            }
        } else {
            proof = await loadProof(...parseInput(input));
        }
        checks = await verify(proof, { fetchJson: flag('offline') ? null : defaultFetchJson });
    } catch (error) {
        const message = error instanceof NotCheckable ? error.message : `Could not check this proof: ${error.message}`;
        if (asJson) console.log(JSON.stringify({ passed: false, error: message }));
        else console.error(message);
        return 2;
    }
    const good = passed(checks);
    if (asJson) {
        console.log(JSON.stringify({ passed: good, id: proof.id, proof_url: proof.proof_url, version: Number(proof.version || 1), result: resultLine(proof), checks }, null, 2));
    } else {
        const marks = { ok: '✓', fail: '✗', skip: '–' };
        const method = proof.drand ? 'scheduled draw with drand' : `Lock v${Number(proof.version || 1)}`;
        console.log(`SpinProof verifier ${VERSION}\nProof   ${proof.proof_url || proof.id}\nTitle   ${proof.title} · spin ${proof.spin_number} · ${method}\nResult  ${resultLine(proof)}\n`);
        for (const check of checks) console.log(`  ${marks[check.status]} ${check.text}`);
        const real = checks.filter((c) => c.status !== 'skip').length;
        console.log(good ? `\nPASSED: all ${real} checks passed. Nothing was changed after the lock.` : '\nFAILED: at least one check did not pass. This result does not match its lock.');
    }
    return good ? 0 : 1;
}

if (typeof process !== 'undefined' && process.argv?.[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/').split('/').pop())) {
    process.exitCode = await main(process.argv.slice(2));
}
