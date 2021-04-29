from vulnerability_mapping import vulnerability_mapping


get_swc_id = lambda issue: issue['swc-id'].strip()
get_category = lambda issue: vulnerability_mapping[get_swc_id(issue)]
get_line_number = lambda issue: issue.get('lineno')


def get_issues(analysis):
    for issue in analysis['issues']:
        yield get_swc_id(issue), get_line_number(issue)
