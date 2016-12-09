#!/usr/bin/env python2.7

import re

from junit import write_junit


def split_kmemleak(entry):
    lines = entry.split('\n')
    msg = ' '.join(lines[:2]).replace('"', '&quot;')
    dump = '\n'.join(lines[2:])
    return msg, dump


with open('kmemleak') as f:
    kmemleak = f.read()[:-1]

entries = [split_kmemleak(e) for e in re.split(r'\n(?=[^ ])', kmemleak) if e]
write_junit('kmemleak', 'kmemleak.xml', entries)
