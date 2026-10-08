"""Writes what plaso's plist_default plugin reads from each property list
given to it (psort JSON lines, see README), one line per event, sorted:
the file name, the root (the path of dictionary keys above the key, empty
at the top), the key, and its date in microseconds since 1970.

Tabs, line breaks and other control characters, and "%", are written
"%XX" (hexadecimal), so each event stays on one line; UTF-16 surrogates
left unpaired, which Python keeps, "%uXXXX".

Run: python3 -I gen_plist_keys.py plist.jsonl > plaso-plist-keys.tsv
"""

import json
import sys


def escape(text):
    return "".join(escaped(c) for c in text)


def escaped(c):
    if c == "%" or ord(c) < 0x20 or c == "\x7f":
        return f"%{ord(c):02X}"
    if 0xD800 <= ord(c) <= 0xDFFF:
        return f"%u{ord(c):04X}"
    return c


lines = []
for name in sys.argv[1:]:
    for line in open(name, encoding="utf-8"):
        event = json.loads(line)
        if event["parser"] != "plist/plist_default":
            continue
        file = event["pathspec"]["location"].rsplit("/", 1)[-1]
        lines.append("\t".join([file, escape(event["root"]), escape(event["key"]), str(event["timestamp"])]))
for line in sorted(lines):
    print(line)
