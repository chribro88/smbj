"""Regression tests on the two sanitized captures supplied with the SMBJ archive."""
import json
import unittest
from pathlib import Path
from audit_gmac_nonce_trace import audit, TraceError

HERE = Path(__file__).resolve().parent.parent


class GmacTraceAuditTest(unittest.TestCase):
    def test_go_samba_legitimate_bindings_expose_two_collisions(self):
        data = json.loads((HERE / 'gmac-binding-observation.json').read_text())
        result = audit(data)
        self.assertEqual(17, result['independently_verified_signed_events'])
        self.assertEqual(2, result['different_message_reuses'])
        self.assertEqual(3, result['key_nonce_reuses'])
        self.assertEqual([(12, 20), (13, 21)],
                         [(r['first_event'], r['second_event'])
                          for r in result['reuses'] if r['different_message']])

    def test_auxiliary_research_has_no_collisions_in_observed_runs(self):
        data = json.loads((HERE / 'auxiliary-observation.json').read_text())
        result = audit(data)
        self.assertGreater(result['independently_verified_signed_events'], 0)
        self.assertEqual(0, result['different_message_reuses'])
        self.assertEqual(4, len(result['events_per_run']))
        self.assertEqual(6, result['excluded_partial_negative_control_events'])
        self.assertEqual(0, result['key_nonce_reuses'],
                         'Only the four complete positive runs are scored')

    def test_rejects_tampered_nonce_metadata(self):
        data = json.loads((HERE / 'gmac-binding-observation.json').read_text())
        next(event for event in data['events'] if event.get('signed'))['nonce'] = '00' * 12
        with self.assertRaises(TraceError):
            audit(data)

    def test_does_not_accept_unverified_events(self):
        data = json.loads((HERE / 'gmac-binding-observation.json').read_text())
        next(event for event in data['events'] if event.get('signed'))['independently_verified'] = False
        with self.assertRaises(TraceError):
            audit(data)


if __name__ == '__main__':
    unittest.main()
