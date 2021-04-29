import itertools
import json
import os
from functools import partial

from collections import defaultdict
from pathlib import Path
from pytablewriter import MarkdownTableWriter
from vulnerability_mapping import ROOT, vulnerabilities, vulnerability_mapping
import mythril_out


ROOT = Path(ROOT)
CURATED_MYTHRIL = ROOT / 'results' / "mythril" / "curated"

flatten_vulnerability = lambda vuln: [(vuln['category'], line) for line in vuln['lines']]
def flatten_vulnerabilities(vulns):
    vulns['vulnerabilities'] = list(itertools.chain(*map(flatten_vulnerability, vulns['vulnerabilities'])))
    return vulns


def process_found_issue(issue, negatives, positives):
    found_issue = mythril_out.get_category(issue), mythril_out.get_line_number(issue)

    filename = issue.get('filename', '').lstrip('/')
    file_vulns = negatives.get(filename, {'vulnerabilities': []})
    if found_issue in file_vulns['vulnerabilities']:
        file_vulns['vulnerabilities'].remove(found_issue)
    else:
        positives[filename].append(found_issue)


def get_false_negatives_positives():
    negatives = {obj['path']: flatten_vulnerabilities(obj) for obj in vulnerabilities}
    positives = defaultdict(list)

    curated_results = CURATED_MYTHRIL.rglob("result.json")
    for path in curated_results:
        with open(path, "r") as f:
            result = json.load(f)
        if not result['analysis']: continue
        for issue in result['analysis']['issues']:
            process_found_issue(issue, negatives, positives)

    return filter(lambda c: c['vulnerabilities'], negatives.values()), positives


false_positives_table, false_negatives_table = '', ''
MarkdownTable = partial(MarkdownTableWriter, headers=["category", "line"])
false_negatives, false_positives = get_false_negatives_positives()

for contract in false_negatives:
    writer = MarkdownTable(
            table_name=contract['path'],
            value_matrix=contract['vulnerabilities'],
        )
    false_negatives_table += writer.dumps()

for path, results in false_positives.items():
    writer = MarkdownTable(table_name=path, value_matrix=results)
    false_positives_table += writer.dumps()

with open(ROOT / 'mythril_false_negatives.md', 'w') as f:
    f.write(false_negatives_table)

with open(ROOT / 'mythril_false_positives.md', 'w') as f:
    f.write(false_positives_table)
