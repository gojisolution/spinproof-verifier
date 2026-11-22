"""Tests for python/spinproof_verify.py. Offline: no network. Run: python -m unittest discover tests"""

import copy
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'python'))

import spinproof_verify as sv  # noqa: E402

FIXTURES = sorted((ROOT / 'fixtures').glob('v[0-9]-*.json'))
VECTORS = json.loads((ROOT / 'fixtures' / 'vectors.json').read_text(encoding='utf-8'))


def load(path):
    return json.loads(path.read_text(encoding='utf-8'))


def fails(proof):
    return not sv.passed(sv.verify(proof, fetch=None))


class Vectors(unittest.TestCase):
    def test_v1(self):
        v = VECTORS
        self.assertEqual(sv.fingerprint(v['entries']), v['fingerprint'])
        self.assertEqual(sv.lock_v1(v['secret']), v['lock_v1'])
        self.assertEqual(sv.pick_indexes(v['secret'], v['fingerprint'], 5, 2), v['pick_v1_2'])

    def test_weighted(self):
        w = VECTORS['weighted']
        self.assertEqual(sv.fingerprint(w['entries']), w['fingerprint'])
        self.assertEqual([sv.weighted(e)[1] for e in w['entries']], w['weights'])
        self.assertEqual(sv.weighted('Diego ×4'), ('Diego', 4))
        self.assertEqual(sv.weighted('Room 101'), ('Room 101', 1))
        self.assertEqual(sv.weighted('Too much *101'), ('Too much *101', 1))
        self.assertEqual(sv.pick_indexes(VECTORS['secret'], w['fingerprint'], 5, 3, w['weights']), w['pick_v1_3'])

    def test_v2(self):
        v, v2 = VECTORS, VECTORS['v2']
        stmt = sv.statement(v['fingerprint'], 5, 'pick', 2, None, False, None)
        self.assertEqual(stmt, v2['statement'])
        self.assertEqual(sv.lock_v2(v['secret'], stmt), v2['lock'])
        seed = sv.spin_seed(v['secret'], v['client_seed'])
        self.assertEqual(seed, v2['seed'])
        self.assertEqual(sv.pick_indexes(seed, v['fingerprint'], 5, 2), v2['pick_2'])
        self.assertEqual(sv.spin_seed(v['secret'], ''), v2['seed_without_browser_number'])
        self.assertEqual(sv.spin_seed(v['secret'], None), v2['seed_without_browser_number'])

    def test_v2_linked(self):
        v, linked = VECTORS, VECTORS['v2_linked']
        self.assertEqual(sv.fingerprint(linked['prizes']), linked['prizes_fingerprint'])
        stmt = sv.statement(v['fingerprint'], 5, 'linked', 2, None, False, linked['prizes_fingerprint'])
        self.assertEqual(sv.lock_v2(v['secret'], stmt), linked['lock'])
        seed = sv.spin_seed(v['secret'], v['client_seed'])
        self.assertEqual(sv.pick_indexes(seed, linked['prizes_fingerprint'], 3, 2), linked['prize_pick_2'])

    def test_teams_and_drand_rounds(self):
        self.assertEqual(sv.deal_teams([0, 1, 2, 3, 4], 2), [[0, 2, 4], [1, 3]])
        self.assertEqual(sv.first_round_after(sv.QUICKNET_GENESIS + 0.5), 2)
        self.assertEqual(sv.first_round_after(sv.QUICKNET_GENESIS + 3), 2)


class Fixtures(unittest.TestCase):
    def test_every_fixture_passes(self):
        self.assertGreaterEqual(len(FIXTURES), 13)
        for path in FIXTURES:
            with self.subTest(path.name):
                self.assertTrue(sv.passed(sv.verify(load(path), fetch=None)))

    def test_changed_winner_fails(self):
        for path in FIXTURES:
            proof = load(path)
            with self.subTest(path.name):
                changed = copy.deepcopy(proof)
                first = changed['winners'][0]
                first['index'] = (first['index'] + 1) % proof['entries_count']
                self.assertTrue(fails(changed))

    def test_changed_secret_or_lock_fails(self):
        for path in FIXTURES:
            proof = load(path)
            with self.subTest(path.name):
                self.assertTrue(fails({**proof, 'secret': '0' * 64}))
                self.assertTrue(fails({**proof, 'commitment': '0' * 64}))

    def test_v2_settings_and_browser_number_are_sealed(self):
        proof = load(ROOT / 'fixtures' / 'v2-pick-hidden.json')
        self.assertTrue(fails({**proof, 'winners_count': 2, 'winners': proof['winners'][:2]}))
        self.assertTrue(fails({**proof, 'mode': 'eliminate'}))
        self.assertTrue(fails({**proof, 'client_seed': 'f' * 64}))
        self.assertTrue(fails({**proof, 'client_seed': ''}))
        self.assertTrue(fails({**proof, 'version': 1}))

    def test_automatic_reveal_is_a_note_not_a_failure(self):
        checks = sv.verify(load(ROOT / 'fixtures' / 'v2-auto-revealed.json'), fetch=None)
        self.assertTrue(sv.passed(checks))
        self.assertTrue(any(c.status == 'skip' and 'Browser number: none' in c.text for c in checks))

    def test_linked_teams_and_drand_tampering_fails(self):
        linked = load(ROOT / 'fixtures' / 'v2-linked.json')
        self.assertTrue(fails({**linked, 'prize_winners': list(reversed(linked['prize_winners']))}))
        self.assertTrue(fails({**linked, 'prizes': linked['prizes'][:-1]}))
        teams = load(ROOT / 'fixtures' / 'v2-teams.json')
        self.assertTrue(fails({**teams, 'teams': list(reversed(teams['teams']))}))
        drand = load(ROOT / 'fixtures' / 'v1-drand.json')
        self.assertTrue(fails({**drand, 'drand': {**drand['drand'], 'randomness': '0' * 64}}))
        later = {**drand['drand'], 'entries_closed_at': '2030-01-01T00:00:00.000Z'}
        self.assertTrue(fails({**drand, 'drand': later}))

    def test_drand_network_comparison(self):
        drand = load(ROOT / 'fixtures' / 'v1-drand.json')
        beacon = {'randomness': drand['drand']['randomness'], 'signature': drand['drand']['signature']}
        self.assertTrue(sv.passed(sv.verify(drand, fetch=lambda url: beacon)))
        self.assertTrue(fails_with(drand, {'randomness': '1' * 64, 'signature': beacon['signature']}))

    def test_hidden_names_are_a_note(self):
        checks = sv.verify(load(ROOT / 'fixtures' / 'v1-weighted-hidden.json'), fetch=None)
        self.assertEqual(checks[-1].status, 'skip')

    def test_unrevealed_spin_cannot_be_checked(self):
        proof = {**load(ROOT / 'fixtures' / 'v1-pick.json'), 'secret': None, 'revealed_at': None}
        with self.assertRaises(sv.NotCheckable):
            sv.verify(proof)


def fails_with(proof, beacon):
    return not sv.passed(sv.verify(proof, fetch=lambda url: beacon))


class Input(unittest.TestCase):
    def test_links_and_codes(self):
        self.assertEqual(sv.parse_input('https://spinproof.app/r/tddtfwrt'), ('spin', 'tddtfwrt'))
        self.assertEqual(sv.parse_input('spinproof.app/r/TDDTFWRT/'), ('spin', 'tddtfwrt'))
        self.assertEqual(sv.parse_input('https://spinproof.app/r/tddtfwrt?lang=es#x'), ('spin', 'tddtfwrt'))
        self.assertEqual(sv.parse_input('https://www.spinproof.app/d/fb22xr68'), ('draw', 'fb22xr68'))
        self.assertEqual(sv.parse_input('  fb22xr68 '), ('any', 'fb22xr68'))

    def test_other_sites_and_pages_are_refused(self):
        for value in ['https://example.com/r/tddtfwrt', 'https://spinproof.app/giveaway-picker',
                      'https://spinproof.app/r/../etc', 'not a link!']:
            with self.subTest(value), self.assertRaises(sv.NotCheckable):
                sv.parse_input(value)


class CommandLine(unittest.TestCase):
    def test_exit_codes(self):
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(sv.main(['--offline', '--file', str(ROOT / 'fixtures' / 'v2-pick.json')]), 0)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(sv.main(['https://example.com/r/abcdefgh']), 2)


if __name__ == '__main__':
    unittest.main()
