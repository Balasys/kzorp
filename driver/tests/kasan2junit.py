#!/usr/bin/env python2

import re

from junit import write_junit


def split_kasan(element):
    lines = element.split('\n')
    msg = ' '.join(lines[1:3])
    dump = '\n'.join(lines[4:-2])
    return msg, dump


with open('dmesg') as f:
    dmesg = f.read()

elements = re.findall(r'\[ *?[\d.]+\] ==================================================================$.*? ==================================================================$', dmesg, re.MULTILINE | re.DOTALL)

write_junit('kasan', 'kasan.xml', [split_kasan(e) for e in elements])
