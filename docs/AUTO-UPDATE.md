# Automatic update check

Every GNULTE executable checks for a newer release when it starts in an
interactive terminal. The check is a single HTTPS request for the `VERSION`
file in the project's `main` branch, with a two-second timeout. Nothing is
downloaded unless you say yes.

## What you see

If a newer version is available:

```
GNULTE v17.0 — update available: v17.1. Install now? [y/N]
```

`y` or `yes` runs `update.sh`: it downloads a fresh source archive into a
temporary directory, builds it there, and runs the existing `install.sh`
(which asks for sudo when needed). Your current working tree is never touched.
Any other answer declines the prompt; the same version is not offered again
for seven days.

If the network is unavailable, or the version file cannot be read, startup
continues silently. There is no retry loop and no background service.

## When the check is skipped

The check does not run when:

- the command is `--version`, `-v`, `--help`, `-h`, or `--no-update-check`;
- stdout or stdin is not a terminal (pipes, scripts, CI);
- `GNULTE_NO_UPDATE` is set in the environment; or
- **Settings → Terminal & UI → check for updates on startup** is off.

## Files

- `VERSION` — the release number published for the updater to read.
- `internal/update` — version fetch, comparison, prompt, and snooze state.
- `update.sh` — temporary-directory source build and install.
- `~/.config/gnulte-go/update-state.json` — records a declined version.

## Safety notes

The updater installs the whole suite at once, because the binaries share one
version. It does not remove the old version first, and it does not change any
configuration or saved reports. If the install fails, the previously installed
binaries remain in place.
