// Tests for js/spinproof-verify.mjs. Offline: no network. Run: node --test tests/
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { test } from 'node:test';
import * as sv from '../js/spinproof-verify.mjs';

const dir = new URL('../fixtures/', import.meta.url);
const load = (name) => JSON.parse(readFileSync(new URL(name, dir), 'utf8'));
const FIXTURES = readdirSync(dir).filter((f) => /^v\d-.*\.json$/.test(f)).sort();
const V = load('vectors.json');
const offline = { fetchJson: null };
const fails = async (proof, options = offline) => !sv.passed(await sv.verify(proof, options));

test('known answers: Lock v1 and weighted draws', async () => {
    assert.equal(await sv.fingerprint(V.entries), V.fingerprint);
    assert.equal(await sv.lockV1(V.secret), V.lock_v1);
    assert.deepEqual(await sv.pickIndexes(V.secret, V.fingerprint, 5, 2), V.pick_v1_2);
    assert.equal(await sv.fingerprint(V.weighted.entries), V.weighted.fingerprint);
    assert.deepEqual(V.weighted.entries.map((e) => sv.weighted(e)[1]), V.weighted.weights);
    assert.deepEqual(sv.weighted('Diego ×4'), ['Diego', 4]);
    assert.deepEqual(sv.weighted('Room 101'), ['Room 101', 1]);
    assert.deepEqual(sv.weighted('Too much *101'), ['Too much *101', 1]);
    assert.deepEqual(await sv.pickIndexes(V.secret, V.weighted.fingerprint, 5, 3, V.weighted.weights), V.weighted.pick_v1_3);
});

test('known answers: Lock v2', async () => {
    const stmt = sv.statement(V.fingerprint, 5, 'pick', 2, null, false, null);
    assert.equal(stmt, V.v2.statement);
    assert.equal(await sv.lockV2(V.secret, stmt), V.v2.lock);
    const seed = await sv.spinSeed(V.secret, V.client_seed);
    assert.equal(seed, V.v2.seed);
    assert.deepEqual(await sv.pickIndexes(seed, V.fingerprint, 5, 2), V.v2.pick_2);
    assert.equal(await sv.spinSeed(V.secret, ''), V.v2.seed_without_browser_number);
    const linked = sv.statement(V.fingerprint, 5, 'linked', 2, null, false, V.v2_linked.prizes_fingerprint);
    assert.equal(await sv.fingerprint(V.v2_linked.prizes), V.v2_linked.prizes_fingerprint);
    assert.equal(await sv.lockV2(V.secret, linked), V.v2_linked.lock);
    assert.deepEqual(await sv.pickIndexes(seed, V.v2_linked.prizes_fingerprint, 3, 2), V.v2_linked.prize_pick_2);
    assert.deepEqual(sv.dealTeams([0, 1, 2, 3, 4], 2), [[0, 2, 4], [1, 3]]);
    assert.equal(sv.firstRoundAfter(sv.QUICKNET_GENESIS + 0.5), 2);
});

test('every fixture passes', async () => {
    assert.ok(FIXTURES.length >= 13);
    for (const name of FIXTURES) assert.ok(sv.passed(await sv.verify(load(name), offline)), name);
});

test('a changed winner, secret or lock fails', async () => {
    for (const name of FIXTURES) {
        const proof = load(name);
        const changed = structuredClone(proof);
        changed.winners[0].index = (changed.winners[0].index + 1) % proof.entries_count;
        assert.ok(await fails(changed), `${name}: winner`);
        assert.ok(await fails({ ...proof, secret: '0'.repeat(64) }), `${name}: secret`);
        assert.ok(await fails({ ...proof, commitment: '0'.repeat(64) }), `${name}: lock`);
    }
});

test('Lock v2 seals the settings and the browser number', async () => {
    const proof = load('v2-pick-hidden.json');
    assert.ok(await fails({ ...proof, winners_count: 2, winners: proof.winners.slice(0, 2) }));
    assert.ok(await fails({ ...proof, mode: 'eliminate' }));
    assert.ok(await fails({ ...proof, client_seed: 'f'.repeat(64) }));
    assert.ok(await fails({ ...proof, client_seed: '' }));
    assert.ok(await fails({ ...proof, version: 1 }));
    const auto = await sv.verify(load('v2-auto-revealed.json'), offline);
    assert.ok(sv.passed(auto));
    assert.ok(auto.some((c) => c.status === 'skip' && c.text.startsWith('Browser number: none')));
});

test('linked wheels, teams and drand cannot be changed', async () => {
    const linked = load('v2-linked.json');
    assert.ok(await fails({ ...linked, prize_winners: [...linked.prize_winners].reverse() }));
    assert.ok(await fails({ ...linked, prizes: linked.prizes.slice(0, -1) }));
    const teams = load('v2-teams.json');
    assert.ok(await fails({ ...teams, teams: [...teams.teams].reverse() }));
    const drand = load('v1-drand.json');
    assert.ok(await fails({ ...drand, drand: { ...drand.drand, randomness: '0'.repeat(64) } }));
    assert.ok(await fails({ ...drand, drand: { ...drand.drand, entries_closed_at: '2030-01-01T00:00:00.000Z' } }));
    const beacon = { randomness: drand.drand.randomness, signature: drand.drand.signature };
    assert.ok(sv.passed(await sv.verify(drand, { fetchJson: async () => beacon })));
    assert.ok(await fails(drand, { fetchJson: async () => ({ ...beacon, randomness: '1'.repeat(64) }) }));
});

test('hidden names are a note, and unrevealed spins cannot be checked', async () => {
    assert.equal((await sv.verify(load('v1-weighted-hidden.json'), offline)).at(-1).status, 'skip');
    await assert.rejects(sv.verify({ ...load('v1-pick.json'), secret: null, revealed_at: null }), sv.NotCheckable);
});

test('parseInput reads links and codes and refuses everything else', () => {
    assert.deepEqual(sv.parseInput('https://spinproof.app/r/tddtfwrt'), ['spin', 'tddtfwrt']);
    assert.deepEqual(sv.parseInput('spinproof.app/r/TDDTFWRT/'), ['spin', 'tddtfwrt']);
    assert.deepEqual(sv.parseInput('https://spinproof.app/r/tddtfwrt?lang=es#x'), ['spin', 'tddtfwrt']);
    assert.deepEqual(sv.parseInput('https://www.spinproof.app/d/fb22xr68'), ['draw', 'fb22xr68']);
    assert.deepEqual(sv.parseInput('  fb22xr68 '), ['any', 'fb22xr68']);
    for (const value of ['https://example.com/r/tddtfwrt', 'https://spinproof.app/giveaway-picker', 'https://spinproof.app/r/../etc', 'not a link!']) {
        assert.throws(() => sv.parseInput(value), sv.NotCheckable, value);
    }
});

test('loadProof falls back from a proof code to a scheduled draw', async () => {
    const proof = load('v1-drand.json');
    const fetchJson = async (url) => {
        if (url.includes('/api/spins/')) throw new sv.HttpError(404, url);
        return { draw: { result: proof } };
    };
    assert.equal((await sv.loadProof('any', 'abcdefgh', { fetchJson })).id, proof.id);
    await assert.rejects(sv.loadProof('spin', 'abcdefgh', { fetchJson }), sv.NotCheckable);
    await assert.rejects(sv.loadProof('draw', 'abcdefgh', { fetchJson: async () => ({ draw: { result: null, draw_at: 'later' } }) }), /not happened yet/);
});
