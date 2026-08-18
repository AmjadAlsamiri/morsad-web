"""Compare two local scans of the same authorized target for follow-up."""


def compare_reports(current, previous, labels):
    current_checks = {item['check']: item['passed'] for item in current.get('details', {}).get('checks', [])}
    previous_checks = {item['check']: item['passed'] for item in previous.get('details', {}).get('checks', [])}
    improvements, regressions, unchanged = [], [], []

    for check in sorted(set(current_checks) | set(previous_checks)):
        old = previous_checks.get(check)
        new = current_checks.get(check)
        name = labels.get(check, check)
        if old is False and new is True:
            improvements.append(name)
        elif old is True and new is False:
            regressions.append(name)
        else:
            unchanged.append(name)

    return {
        'score_change': current.get('score', 0) - previous.get('score', 0),
        'previous_score': previous.get('score', 0),
        'current_score': current.get('score', 0),
        'improvements': improvements,
        'regressions': regressions,
        'unchanged_count': len(unchanged),
    }
