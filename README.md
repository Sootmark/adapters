# adapters

Parser adapters: each parser's native output mapped into the Sootmark model.

```toml
[dependencies]
sootmark-adapters = "0.1"
```

Parsers are independent libraries that know nothing about Sootmark. Each module here wraps one and maps its output into `model::Record`s.

Native parsers:

- `prefetch` (`windows.prefetch`): Prefetch files, compressed or not: what ran, how often, when (up to eight run times), from where. Checked against PECmd.
- `utmp` (`linux.utmp`): Linux login records (`wtmp`, `btmp`, `utmp`, rotated copies included): logins with the account, terminal and source address, failed logins (from `btmp`), logouts, boots, run level and clock changes. Checked on plaso's test files.
- `history` (`unix.shell_history`): shell history files (`.bash_history`, `.zsh_history`, `.histfile`, `fish_history`): one record per command, with its time when the shell wrote one (bash only with `HISTTIMEFORMAT`; never dated by the file), zsh's duration, fish's paths, and the account whose home holds the file. Checked on plaso's test files.
- `syslog` (`linux.syslog`): Linux syslog files (`syslog`, `messages`, `auth.log`, `secure`, `kern.log`, `cron`, rotated copies included; classic, RFC 3339 and RFC 5424 lines): every entry, and SSH logins and failures, sudo, su, cron commands and account changes with the account and source address. Classic lines carry no year: it is inferred from the file's modification time and marked. Checked on plaso's test files.
- `registry` (`windows.registry.*`): hives. SYSTEM: ShimCache and services; NTUSER.DAT: UserAssist; SOFTWARE and NTUSER.DAT: Run and RunOnce; UsrClass.dat and NTUSER.DAT: ShellBags; Amcache.hve: every entry (`windows.registry.amcache.*`: files with their SHA-1 and program, programs, shortcuts, driver binaries and packages, devices), both layouts; SYSTEM, every control set: BAM and DAM (`windows.registry.bam`: per user, programs and their last run). A dirty hive is read as it is and reported as skipped. Checked against RECmd, AppCompatCacheParser, SBECmd, AmcacheParser and plaso.
- `lnk` (`windows.lnk`): LNK files: the target, its times as the link saw them, the volume and the machine it was made on.
- `jumplist` (`windows.jumplist`): jump lists, one record per entry. Automatic: last use, pin, access count, machine and MAC, path and link; custom: the category and the link (target and arguments). The application identifier is the file name.
- `evtx`: Windows event logs. One record per event, located by file offset, timed by `TimeCreated`, facets from `System` and `EventData`, descriptive timeline summaries.

Importers of other tools' output:

- `hayabusa`: imports [Hayabusa](https://github.com/Yamato-Security/hayabusa) `dfir-timeline` output, CSV or JSON Lines, any profile. One record per detection, located by line, timed exactly from zoned timestamps (default, `-U`, `-O`, `--rfc-3339`; ambiguous formats are refused with a hint), levels spelled out, event details split into fields and mapped to facets.
- `ez`: imports [EZ Tools](https://ericzimmerman.github.io/) CSV output, recognised by exact header: MFTECmd (`$MFT`, `$J`), LECmd, JLECmd (automatic and custom destinations), RBCmd, EvtxECmd, AmcacheParser (file and program entries), PECmd (and its run timeline), AppCompatCacheParser, SBECmd, RECmd (batch output). Every column is kept; times are read as the UTC EZ writes, each with its meaning (created, modified, first/last seen, deleted, …); `ez.*` namespaces keep EZ's reading apart from Sootmark's own parsers. EvtxECmd's output is checked against the native EVTX parser event by event, and PECmd's run times against Plaso's.
- `plaso`: imports [Plaso](https://github.com/log2timeline/plaso) `psort` output: `json_line` (exact: FILETIME ticks kept, local-by-nature FAT times kept local), `dynamic` and `l2tcsv` (to the second: psort's CSV misprints sub-second fractions that start with a zero). One record per Plaso event, namespaced by Plaso's file-level parser (`plaso.winevtx`, `plaso.mft`, …). Checked against the native EVTX parser record by record.
- `velociraptor`: imports [Velociraptor](https://github.com/Velocidex/velociraptor) artifact results (`results/<Artifact>.json` in a collection). Mapped: `Windows.Forensics.Prefetch`, `Lnk`, `RecycleBin`, `Windows.NTFS.MFT`, `Windows.EventLogs.Evtx`/`EvtxHunter`, `Windows.Forensics.SRUM` sources. Any other artifact is imported generically: every zoned timestamp becomes a time, every value a field. Cross-checked against PECmd, MFTECmd, RBCmd and the native EVTX parser on the same artifacts.

Adapters pass the `conformance` suite. Every fixture is open data or our own synthetic data, and every tool output is real and unaltered unless said otherwise:

- Event logs: five of [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) (CC0, `tests/fixtures/cc0/`). Hayabusa 4.1.0 (every profile and time format), EvtxECmd, plaso and Velociraptor's `EvtxHunter` ran on two of them; each is checked against the native EVTX parser.
- Prefetch: the open files of `sootmark-prefetch` (Eric Zimmerman's test set, MIT, and plaso's, Apache-2.0; `tests/fixtures/prefetch/`). PECmd ran on Windows (that repository's `oracle` workflow); plaso and Velociraptor on the same files, each checked against PECmd, as is the native adapter.
- Linux login records: plaso's utmp test files (Apache-2.0, `tests/fixtures/utmp/`).
- Linux syslog: plaso's syslog test files (Apache-2.0, `tests/fixtures/syslog/`).
- Shell history: plaso's bash, zsh and fish test files (Apache-2.0, `tests/fixtures/history/`).
- Registry: AppCompatCacheParser, SBECmd and RECmd on the MIT-licensed test hives of EZ's [Registry](https://github.com/EricZimmerman/Registry) library (excerpts; RECmd's re-serialised as minimal-quoted CSV); AmcacheParser on plaso's Windows 10 `Amcache.hve` (Apache-2.0).
- SRUM: Velociraptor on plaso's `SRUDB.dat` (Apache-2.0), the first rows of each table.
- The synthetic FIN-WKS-07 artifacts (MFT, USN journal, LNK, jump lists, recycle bin; generated, no real data): EZ Tools, plaso 20260720 and Velociraptor 0.77.2, with the analysis machine's paths replaced.

## Quality

`#![forbid(unsafe_code)]`, `clippy::pedantic` clean, `cargo-deny` (permissive licences, no network crates).

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.
