def write_junit(name, fname, entries):
    with open(fname, 'w') as junit:
        junit.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        junit.write('<testsuite name="{}" tests="{}">\n'.format(name, len(entries)))
        for msg, dump in entries:
            junit.write('    <testcase name="{}">\n'.format(name))
            junit.write('    <failure message="{}">\n        <![CDATA[\n{}\n        ]]>\n    </failure>\n'.format(msg, dump))
            junit.write('    </testcase>\n')
        junit.write('</testsuite>\n')
