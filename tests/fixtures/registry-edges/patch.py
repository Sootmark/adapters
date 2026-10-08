r"""Writes NTUSER-edges.DAT: plaso's NTUSER-WIN7.DAT (tests/fetch-hives.sh
fetches it as plaso-NTUSER-WIN7.DAT) with values changed into the shapes
the test hives lack, to see how plaso reads each:

  Sizes\0, Size #0        QWORD of 6 bytes
  Sizes\0, Font #0        92 bytes typed QWORD
  Sizes\0, Font #1        92 bytes typed DWORD big-endian
  Sizes\0, Flat Menus     DWORD of 2 bytes (inline)
  Sizes\0, DisplayName    REG_SZ of 37 bytes (odd)
  Sizes\0, Font #2        92 bytes typed REG_LINK
  Desktop, Wallpaper      REG_SZ starting with a lone high surrogate
  Desktop, SCRNSAVE.EXE   REG_SZ starting with a lone low surrogate
  Desktop, ScreenSaveTimeOut  REG_SZ starting with a byte order mark
  Desktop, MenuShowDelay  name's first byte 0x92 (Latin-1 name)
  Administrator, CriticalExtensions  REG_MULTI_SZ of 21 bytes (odd)

(Sizes\0 is Control Panel\Appearance\New Schemes\0\Sizes\0, Desktop is
Control Panel\Desktop, Administrator is
Software\Microsoft\Cryptography\CertificateTemplateCache\Administrator.)

Run: python3 -I patch.py plaso-NTUSER-WIN7.DAT NTUSER-edges.DAT
"""

import struct
import sys

BINS = 4096

data = bytearray(open(sys.argv[1], "rb").read())


def value(cell, name):
    """The file offset of the value cell `cell` (its offset in the bins),
    checked to be the value named `name`."""
    at = BINS + cell + 4
    length = struct.unpack_from("<H", data, at + 2)[0]
    assert data[at:at + 2] == b"vk" and data[at + 20:at + 20 + length] == name.encode("latin-1"), name
    return at


def put(at, fmt, number):
    struct.pack_into(fmt, data, at, number)


def first_unit(at, unit):
    """Makes the first UTF-16 unit of the value at `at`'s data `unit`."""
    put(BINS + struct.unpack_from("<I", data, at + 8)[0] + 4, "<H", unit)


put(value(247808, "Size #0") + 4, "<I", 6)
put(value(247272, "Font #0") + 12, "<I", 11)
put(value(247400, "Font #1") + 12, "<I", 5)
put(value(247232, "Flat Menus") + 4, "<I", 0x80000002)
put(value(245664, "DisplayName") + 4, "<I", 37)
put(value(247552, "Font #2") + 12, "<I", 6)
first_unit(value(370608, "Wallpaper"), 0xD800)
first_unit(value(846392, "SCRNSAVE.EXE"), 0xDC00)
first_unit(value(846504, "ScreenSaveTimeOut"), 0xFEFF)
data[value(18816, "MenuShowDelay") + 20] = 0x92
put(value(318104, "CriticalExtensions") + 4, "<I", 21)
open(sys.argv[2], "wb").write(data)
