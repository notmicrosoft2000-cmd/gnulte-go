# Quality-of-life commands

These additions are about avoiding repeated typing, catching problems before a
run, and recovering cleanly when a run is interrupted.

## Shell completions

Generate a completion script for your shell:

```bash
gnulte-hub --completions bash   # or zsh, fish
```

The script covers all eight binaries, their flags, `gnulte-watch top`/`trace`,
`gnulte-report` subcommands, built-in and saved profiles, and Wi-Fi reason
presets. It prints to stdout; nothing is written to your shell startup files.
Source or install it according to your shell's usual method.

## Doctor

```bash
gnulte-hub doctor
```

This runs the same checks as `gnulte-quicksum` and prints a compact PASS/WARN/
FAIL report with hints. It does not change the system. The exit status is 0 when
nothing failed, non-zero when a check failed, so it can be used in scripts.

## On-demand update check

```bash
gnulte --check-update
```

Any tool accepts this flag. It reports the installed and available versions and
exits; in a terminal it also offers the install prompt. The hub has a **Check
for updates now** menu row. See [AUTO-UPDATE.md](AUTO-UPDATE.md).

## Dry run

```bash
gnulte --plan -t 192.168.1.50 -l 300 -j 30 --duration 90
```

`--plan` (alias `--dry-run`) prints the interface, targets, mode, the exact
`tc` tree and change commands, `iptables` rules, the `ip_forward` line, and both
`arpspoof` directions. It needs no root, opens no picker, sends no packets, and
changes nothing. Pass `-t`, `-m`, or `-r` explicitly; `--plan` will not scan the
network to invent targets.

## Forced cleanup

```bash
sudo gnulte --cleanup
sudo gnulte --cleanup --restore-forward
```

Use this after an interrupted or crashed shaping session. It:

1. removes the root `netem` qdisc when one is present;
2. deletes `FORWARD` DROP rules carrying GNULTE's comment marker (new rules are
   marked so unrelated firewall rules are never touched);
3. reports `ip_forward`; with `--restore-forward`, sets it back to 1; and
4. re-announces the real gateway's MAC when the default route is detectable.

Each step is printed as `[✓]` or `[!]`. The command exits 1 if any step had a
problem. `--cleanup` deliberately does **not** run the safety-record handshake
or the sudo re-exec, so it works from a plain root shell.
