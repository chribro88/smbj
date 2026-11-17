#!/usr/bin/env python3
# Copyright (C)2016 - SMBJ Contributors
# Licensed under the Apache License, Version 2.0.
"""Classify a single preserved Gradle matrix iteration; never infer PASS from a skip."""
import csv
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

run = Path(sys.argv[1])
rows = []
for report in sorted((run / 'test-results').glob('TEST-*.xml')):
    for case in ET.parse(report).getroot().iter('testcase'):
        status = 'PASS'
        if case.find('failure') is not None or case.find('error') is not None:
            status = 'FAIL'
        elif case.find('skipped') is not None:
            status = 'SKIP'
        rows.append((case.get('classname'), case.get('name'), status, case.get('time')))
with (run / 'cases.csv').open('w', newline='') as output:
    writer = csv.writer(output)
    writer.writerow(('class', 'test', 'status', 'seconds'))
    writer.writerows(rows)
mandatory = [row for row in rows if not row[1].startswith('serverBindingRejectionPreservesPrimarySession')]
passed = (run / 'exit-status').read_text().strip() == '0' and bool(mandatory) and all(row[2] == 'PASS' for row in mandatory)
# Require every suite and all four modes, so partial XML cannot satisfy the matrix gate.
for suite, count in {'BoundChannelsIT': 4, 'MultichannelProtocolIT': 24,
                     'SingleChannelSigningIT': 4, 'MultichannelMultiEndpointIT': 8}.items():
    selected = [row for row in mandatory if row[0].endswith(suite)]
    passed &= len(selected) == count
    for encryption in ('false', 'true'):
        for write_through in ('false', 'true'):
            mode = f'encryption={encryption}, writeThrough={write_through}'
            passed &= sum(mode in row[1] for row in selected) == count // 4
(run / 'status').write_text('PASS\n' if passed else 'FAIL\n')
sys.exit(0 if passed else 1)
