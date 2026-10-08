"""Writes what plaso's winreg_default plugin reads from each key of the
hives given to it (psort JSON lines, see README), one line per key, sorted:
the hive's file name, the key path, the key's last write (FILETIME, or
plaso's word for a time it hasn't), and the values as plaso's formatter
helper (plaso/formatters/winreg.py) writes them from the event's values:
sorted, "name: [TYPE] data" joined with ", ", "(default)" for the unnamed
value, "(empty)" for missing data or no values. Each line is checked
against plaso's own message, which is that string after "[key path] "
with its line breaks dropped.

Tabs, line breaks and other control characters, and "%", are written
"%XX" (hexadecimal), so each key stays on one line; UTF-16 surrogates
left unpaired, which Python keeps, "%uXXXX".

Run: python3 -I gen_registry_keys.py winreg.jsonl | gzip -9n > plaso-registry-keys.tsv.gz
"""

import json
import sys


def values_line(values):
    if not values:
        return "(empty)"
    parts = []
    for name, data_type, data in sorted((v["name"], v["data_type"], v["data"]) for v in values):
        parts.append(f"{name or '(default)'}: [{data_type}] {data or '(empty)'}")
    return ", ".join(parts)


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
        if event["parser"] != "winreg/winreg_default":
            continue
        path = event["key_path"]
        message = event["message"]
        prefix = f"[{path}] "
        if not message.startswith(prefix):
            sys.exit(f"unexpected message for {path!r}: {message!r}")
        values = values_line(event.get("values"))
        if values.replace("\r", "").replace("\n", "") != message[len(prefix):]:
            sys.exit(f"values of {path!r} aren't plaso's message: {values!r}")
        time = event["date_time"]
        written = str(time["timestamp"]) if time["__class_name__"] == "Filetime" else time["string"]
        file = event["pathspec"]["location"].rsplit("/", 1)[-1]
        lines.append("\t".join([file, escape(path), written, escape(values)]))
for line in sorted(lines):
    print(line)
