#!/usr/bin/env python3
"""Public / held-out assignment for generated corpus cases.

Principle 7 (CLAUDE.md): a held-out corpus that porting work never sees. Cases are grouped into
families (for example the 21 scenario tours); within each family about one third of the members
go to held-out, chosen at random with the recorded seed below, so the split is reproducible and
not chosen by hand. The Stage 0 cases keep the split they were committed with.

  split.py FAMILY NAME [NAME ...]   prints 'public NAME' / 'heldout NAME' lines
"""
import random
import sys

SEED = 20261006          # recorded seed for the split; changing it reshuffles every family
HELDOUT_FRACTION = 1 / 3


def assign(family, names):
    """Deterministic assignment of each name to 'public' or 'heldout'."""
    names = sorted(names)
    rng = random.Random(f'{SEED}:{family}')
    k = max(1, round(len(names) * HELDOUT_FRACTION)) if len(names) > 1 else 0
    held = set(rng.sample(names, k))
    return {n: ('heldout' if n in held else 'public') for n in names}


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(2)
    for n, s in sorted(assign(sys.argv[1], sys.argv[2:]).items()):
        print(s, n)
