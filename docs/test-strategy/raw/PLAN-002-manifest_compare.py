"""Compare a pytest -rA output against a PLAN-002 baseline manifest, per test (whitespace-normalized IDs)."""
import re, sys
norm = lambda s: re.sub(r'\s+', ' ', s).strip()
base = {}
for l in open(sys.argv[1]):
    t, s = l.rstrip('\n').rsplit('\t', 1); base[norm(t)] = s
now = {}
for l in open(sys.argv[2]):
    m = re.match(r'^(PASSED|FAILED|ERROR|XFAIL|XPASS) (tests/.*)$', l.rstrip('\n'))
    if not m: continue
    t = m.group(2)
    if m.group(1) != 'PASSED' and ' - ' in t: t = t.split(' - ')[0]
    now.setdefault(norm(t), m.group(1))
bad = 0
for t, s in sorted(base.items()):
    n = now.get(t, 'MISSING')
    if n != s and not (s == 'XFAIL' and n == 'PASSED'):
        bad += 1; print('REGRESSION', s, '->', n, t[:160])
print(f'baseline={len(base)} current={len(now)} regressions={bad} new={len(set(now)-set(base))}')
if len(sys.argv) > 3:
    with open(sys.argv[3], 'w') as f:
        for t, s in sorted(now.items()): f.write(f'{t}\t{s}\n')
