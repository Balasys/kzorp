#!/usr/bin/env python2.7

import re


with open('kmemleak') as f:
    kmemleak = f.read()[:-1]

entries = [e for e in re.split(r'\n(?=[^ ])', kmemleak) if e]
output = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<testsuite name="kmemleak" tests="{0}">'
).format(len(entries))
for e in entries:
    e_lines = e.split('\n')

    e_msg = ' '.join(e_lines[:2]).replace('"', '&quot;')
    e_dump = '\n'.join(e_lines[2:])

    output += (
            '<testcase name="kmemleak">'
            '<failure message="{}"><![CDATA[{}]]></failure>'
            '</testcase>'
    ).format(e_msg, e_dump)

output += (
            '</testsuite>'
)

with open('kmemleak.xml', 'w') as f:
    f.write(output)
