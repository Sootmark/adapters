"""Writes the ScreenConnect samples of this folder; no open ones exist.

- system.config and user.config: .NET settings files as the client keeps
  them (the section public scripts read the relay from, and the launch
  parameters ConnectWise's integration guide names; the setting names are
  made up).
- Session.db: a SQLite database with the four tables ScreenConnect's
  documentation and reports name (Session, SessionConnection, SessionEvent,
  SessionConnectionEvent), with the columns its reports name. ConnectWise
  doesn't publish the schema: the column types are assumptions (GUIDs as
  .NET's 16 bytes, times as text, UTC), and a few values are stored in the
  other type SQLite allows, to check the reader takes either. With
  secure_delete off, January's 240 command events are purged as
  ScreenConnect's database maintenance does (by Time), and two of February's
  deleted one by one; deleted.tsv lists every event deleted.

Run: python3 -I make.py (in this folder). Identifiers, names and addresses
are made up (documentation ranges).
"""

import sqlite3
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent

SYSTEM_CONFIG = """<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <ScreenConnect.ApplicationSettings>
    <setting name="ClientLaunchParametersConstraint" serializeAs="String">
      <value>?h=relay.example.net&amp;p=8041&amp;k=BgIAAACkAABSU0ExAAgAAAEAAQCx%2bS9qL0mR%2fWz%3d</value>
    </setting>
  </ScreenConnect.ApplicationSettings>
</configuration>
"""

USER_CONFIG = """<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <userSettings>
    <ScreenConnect.UserInterfaceSettings>
      <setting name="LastFileTransferDirectory" serializeAs="String">
        <value>C:\\Users\\alice\\Documents\\Payroll &amp; HR</value>
      </setting>
      <setting name="LaunchParameters" serializeAs="String">
        <value>?e=Access&amp;y=Guest&amp;h=relay.example.net&amp;p=8041&amp;s=6f1b3c3e-2a4d-4c5e-9f00-1a2b3c4d5e6f&amp;k=BgIAAACk&amp;c=Example+Co&amp;c=&amp;c=Finance%20laptop</value>
      </setting>
      <setting name="RecentFolders" serializeAs="Xml">
        <value>
          <ArrayOfString xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <string>C:\\Temp</string>
          </ArrayOfString>
        </value>
      </setting>
    </ScreenConnect.UserInterfaceSettings>
  </userSettings>
</configuration>
"""


def guid(text):
    return uuid.UUID(text).bytes_le


SESSION_A = "6f1b3c3e-2a4d-4c5e-9f00-1a2b3c4d5e6f"
SESSION_B = "0a0b0c0d-1111-4222-8333-444455556666"
HOST_CONNECTION = "11111111-2222-4333-8444-555555555555"
GUEST_CONNECTION = "22222222-3333-4444-8555-666666666666"
EVENT = "aaaaaaaa-0000-4000-8000-{:012d}"


def main():
    (HERE / "system.config").write_text(SYSTEM_CONFIG, encoding="utf-8")
    (HERE / "user.config").write_bytes(b"\xef\xbb\xbf" + USER_CONFIG.encode("utf-8"))
    path = HERE / "Session.db"
    path.unlink(missing_ok=True)
    db = sqlite3.connect(path)
    db.executescript("""
        PRAGMA secure_delete = OFF;
        PRAGMA page_size = 4096;
        CREATE TABLE Session (SessionID BLOB PRIMARY KEY, SessionType TEXT, Name TEXT,
            Host TEXT, CustomProperty1 TEXT, CustomProperty2 TEXT, CustomProperty3 TEXT,
            CustomProperty4 TEXT, CustomProperty5 TEXT, CustomProperty6 TEXT,
            CustomProperty7 TEXT, CustomProperty8 TEXT);
        CREATE TABLE SessionConnection (SessionID BLOB, ConnectionID BLOB PRIMARY KEY,
            ProcessType INTEGER, ParticipantName TEXT, NetworkAddress TEXT, ClientType TEXT,
            ClientVersion TEXT, ConnectedTime DATETIME, DisconnectedTime DATETIME);
        CREATE TABLE SessionEvent (SessionID BLOB, EventID BLOB PRIMARY KEY,
            ConnectionID BLOB, Time DATETIME, EventType INTEGER, Host TEXT, Data TEXT,
            EventAttributes INTEGER);
        CREATE TABLE SessionConnectionEvent (SessionID BLOB, ConnectionID BLOB,
            EventID BLOB PRIMARY KEY, Time DATETIME, EventType INTEGER, Data TEXT,
            EventAttributes INTEGER);
    """)
    db.executemany("INSERT INTO Session VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", [
        (guid(SESSION_A), "Access", "FIN-LAPTOP-07", "tech1", "Example Co", None, None,
         "Workstation", "", None, None, None),
        (guid(SESSION_B), "Support", "Untitled Session", "tech2", None, None, None, None,
         None, None, None, None),
    ])
    db.executemany("INSERT INTO SessionConnection VALUES (?,?,?,?,?,?,?,?,?)", [
        (guid(SESSION_A), guid(HOST_CONNECTION), "Host", "tech1", "203.0.113.50",
         "DotNetWinForms", "23.9.8.8811", "2024-02-21 02:13:44.1234567", "2024-02-21 02:41:09.5000000"),
        # A process type stored as a number, a disconnection not yet written.
        (guid(SESSION_A), guid(GUEST_CONNECTION), 1, "FIN-LAPTOP-07", "198.51.100.23",
         "DotNetWinForms", "23.9.8.8811", "2024-02-21 02:13:40", None),
    ])
    session_events = [
        (guid(SESSION_A), guid(EVENT.format(1)), None, "2024-02-21 02:14:02.0000001", 44, "tech1",
         "#!ps\nwhoami /all", 0),
        (guid(SESSION_A), guid(EVENT.format(2)), None, "2024-02-21 02:15:10.0000000", 44, "tech1",
         "net user backdoor P4ssw0rd! /add", 0),
        (guid(SESSION_A), guid(EVENT.format(3)), guid(HOST_CONNECTION), "2024-02-21 02:16:00", 2,
         "tech1", None, 0),
        # An event type stored as its name.
        (guid(SESSION_B), guid(EVENT.format(4)), None, "2024-02-21 03:00:00.5", "CreatedSession",
         "tech2", None, 0),
    ]
    db.executemany("INSERT INTO SessionEvent VALUES (?,?,?,?,?,?,?,?)", session_events)
    connection_events = [
        (guid(SESSION_A), guid(GUEST_CONNECTION), guid(EVENT.format(11)), "2024-02-21 02:14:05.2500000",
         70, "fin-laptop-07\\alice", 0),
        (guid(SESSION_A), guid(GUEST_CONNECTION), guid(EVENT.format(12)), "2024-02-21 02:15:13.0000000",
         70, "The command completed successfully.", 0),
        (guid(SESSION_A), guid(HOST_CONNECTION), guid(EVENT.format(13)), "2024-02-21 02:20:31.7500000",
         27, "mimikatz.zip", 0),
    ]
    db.executemany("INSERT INTO SessionConnectionEvent VALUES (?,?,?,?,?,?,?)", connection_events)
    old_commands = [
        (guid(SESSION_A), guid(EVENT.format(1000 + n)), None,
         f"2024-01-{1 + n % 28:02d} 10:{n % 60:02d}:00.0000000", 44, "tech1", f"dir C:\\Users\\{n}", 0)
        for n in range(120)
    ]
    old_output = [
        (guid(SESSION_A), guid(GUEST_CONNECTION), guid(EVENT.format(2000 + n)),
         f"2024-01-{1 + n % 28:02d} 10:{n % 60:02d}:01.0000000", 70, f"Volume in drive C has no label ({n})", 0)
        for n in range(120)
    ]
    db.executemany("INSERT INTO SessionEvent VALUES (?,?,?,?,?,?,?,?)", old_commands)
    db.executemany("INSERT INTO SessionConnectionEvent VALUES (?,?,?,?,?,?,?)", old_output)
    db.commit()
    # The maintenance purge, then two events deleted by hand: their records
    # stay in the freed space.
    db.execute("DELETE FROM SessionEvent WHERE Time < '2024-02-01'")
    db.execute("DELETE FROM SessionConnectionEvent WHERE Time < '2024-02-01'")
    db.execute("DELETE FROM SessionEvent WHERE EventID = ?", (session_events[1][1],))
    db.execute("DELETE FROM SessionConnectionEvent WHERE EventID = ?", (connection_events[1][2],))
    db.commit()
    deleted = old_commands + [session_events[1]]
    deleted_connection = old_output + [connection_events[1]]
    db.close()
    with open(HERE / "deleted.tsv", "w", encoding="utf-8") as out:
        for row in deleted:
            out.write(f"session\t{uuid.UUID(bytes_le=row[1])}\t{row[3]}\t{row[4]}\t{row[6]}\n")
        for row in deleted_connection:
            out.write(f"connection\t{uuid.UUID(bytes_le=row[2])}\t{row[3]}\t{row[4]}\t{row[5]}\n")


main()
