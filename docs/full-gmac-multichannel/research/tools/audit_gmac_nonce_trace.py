#!/usr/bin/env python3
"""Audit *sanitized* independently verified SMB 3.1.1 GMAC trace metadata.

This tool never processes raw signing keys, authentication tokens or packet data.
Results are evidence for the specified trace, not an end-to-end protocol proof.
"""
import argparse
import collections
import json
import re
import sys
from pathlib import Path

SMB2_CANCEL = 12
MAX_MID = (1 << 64) - 1


class TraceError(ValueError):
    pass


def validate_nonce(message_id, server, command, nonce):
    if not isinstance(message_id, int) or not 0 <= message_id <= MAX_MID:
        raise TraceError('Invalid unsigned SMB MessageId')
    if not isinstance(command, int) or command < 0:
        raise TraceError('Invalid SMB command')
    suffix = (1 if server else 0) | (2 if command == SMB2_CANCEL else 0)
    calculated = message_id.to_bytes(8, 'little') + suffix.to_bytes(4, 'little')
    if calculated.hex() != nonce.lower():
        raise TraceError('Trace GMAC nonce does not match MS-SMB2 3.1.4.1')


def _from_go(data):
    if not isinstance(data.get('events'), list):
        raise TraceError('Expected JSON events')
    for event in data['events']:
        if not event.get('signed'):
            continue
        if event.get('independently_verified') is not True:
            raise TraceError('Signed Go event is not independently verified')
        yield dict(run='go-smb2', event=event['event_id'], connection=event['connection'],
                   key=event['key_id'], nonce=event['nonce'], fingerprint=event['message_fingerprint'],
                   mid=event['message_id'], command=event['command'], server=event['from_server'])


def _from_auxiliary(data):
    if not isinstance(data.get('metadata_lines'), list):
        raise TraceError('Expected sanitized auxiliary metadata_lines')
    for line in data['metadata_lines']:
        if not line.startswith('AUXWIRE '):
            continue
        fields = dict(word.split('=', 1) for word in line.split()[1:] if '=' in word)
        if fields.get('verified') != 'true':
            raise TraceError('Auxiliary event is not independently verified')
        required = {'run', 'event', 'connection', 'keyId', 'nonce', 'fingerprint', 'mid', 'command', 'sender'}
        if not required.issubset(fields):
            raise TraceError('Missing auxiliary event fields: %s' % (required - set(fields)))
        if fields['sender'] not in ('server', 'client'):
            raise TraceError('Invalid SMB sender')
        yield dict(run=fields['run'], event=int(fields['event']), connection=int(fields['connection']),
                   key=fields['keyId'], nonce=fields['nonce'], fingerprint=fields['fingerprint'],
                   mid=int(fields['mid']), command=int(fields['command']), server=fields['sender'] == 'server')


def audit(data):
    if 'events' in data:
        events = _from_go(data)
    elif 'metadata_lines' in data:
        events = _from_auxiliary(data)
    else:
        raise TraceError('Unrecognized trace schema')
    seen = {}
    seen_events = set()
    counts = collections.Counter()
    reuse = []
    excluded_negative_control = 0
    for e in events:
        validate_nonce(e['mid'], e['server'], e['command'], e['nonce'])
        if not re.fullmatch('[0-9a-fA-F]{64}', e['key']) or not re.fullmatch('[0-9a-fA-F]{64}', e['fingerprint']):
            raise TraceError('Expected sanitized keyed 256-bit fingerprints')
        # The unsafe-control deliberately aborts at its first assertion, leaving
        # an incomplete transcript. Do not score it as a positive experiment.
        if e['run'] == 'unsafe-control':
            excluded_negative_control += 1
            continue
        name = (e['run'], e['event'])
        if name in seen_events:
            raise TraceError('Duplicate event identity')
        seen_events.add(name)
        counts[e['run']] += 1
        domain = (e['run'], e['key'].lower(), e['nonce'].lower())
        prev = seen.get(domain)
        if prev is None:
            seen[domain] = e
            continue
        reuse.append({'run': e['run'], 'first_event': prev['event'], 'second_event': e['event'],
                      'first_connection': prev['connection'], 'second_connection': e['connection'],
                      'different_message': prev['fingerprint'].lower() != e['fingerprint'].lower(),
                      'nonce': e['nonce'].lower()})
    return {'independently_verified_signed_events': sum(counts.values()),
            'events_per_run': dict(sorted(counts.items())),
            'excluded_partial_negative_control_events': excluded_negative_control,
            'key_nonce_reuses': len(reuse),
            'different_message_reuses': sum(1 for c in reuse if c['different_message']),
            'reuses': reuse}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('traces', nargs='+', type=Path)
    parser.add_argument('--expect-different-message-reuses', type=int)
    args = parser.parse_args(argv)
    results = {}
    try:
        for path in args.traces:
            results[path.name] = audit(json.loads(path.read_text()))
    except (OSError, ValueError, KeyError, TypeError, TraceError) as e:
        print('TRACE_INVALID: %s' % e, file=sys.stderr)
        return 3
    print(json.dumps(results, indent=2, sort_keys=True))
    count = sum(x['different_message_reuses'] for x in results.values())
    if args.expect_different_message_reuses is not None:
        return 0 if count == args.expect_different_message_reuses else 1
    return 2 if count else 0


if __name__ == '__main__':
    sys.exit(main())
