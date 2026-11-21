# GNULTE terminal surfaces — implementation specification

Scope: `gnulte-hub` front door, shared settings editor, and the live topology view in `gnulte-watch`.
Out of scope: report formats and changes to existing watch screens 1–6.

This revision resolves the read-only audit: the hub mirrors the `gnulte` plain-language flow locally instead of importing a second `main` package; PATH only claims data `gnulte-watch` actually owns; `D discard` must not rewrite the config file.

## 0. Binding constraints

| Area | Verified fact | Decision |
| --- | --- | --- |
| Hub | `cmd/gnulte-hub/main.go` has 9 actions and uses `tui.Menu`; digits 1–9 are immediate. `plainMenu`/`ParseMenuChoice` provide the non-TTY path. | Keep `tui.Menu` for H1/H2/H3. Add context with new `tui.MenuWith` options. All existing action labels and numbers stay unchanged. |
| Plain-language flow | `cmd/gnulte/simple.go` and `cmd/gnulte/menu.go` are in `package main` for the `gnulte` binary. `gnulte-hub` is a different `package main` and cannot import them. | Mirror the exact menu strings and profile mapping in the hub. Do not try to import `simple.go` or `paramsWizard`. Direct numbers are entered in the hub and passed to `gnulte` with `--from-hub`. |
| `Config.Advanced` | JSON key `advanced` means "echo every tc/arpspoof/sysctl command"; default is `true`. | Do **not** use it as a UI mode. UI mode is **Detailed controls**, backed by `hub_detailed`. `advanced` keeps its key, value and behaviour; only its visible label changes to `echo commands in sessions`. |
| Settings editor | `internal/settings/ui.go` uses one `editItem` list with `get`/`set`/`def` and five category heads. `Esc` saves & exits. Callers save the returned config after `Edit`. | Keep the item model and category strings. Add five pages, filter, changed-only view, explicit `s`/`D`. Change `Edit` to return a save flag so `D` leaves disk untouched. |
| Monitor dashboard | `internal/monitor` already samples at 1 Hz; `internal/monitor/monitor.go` holds shaping state that `gnulte-watch` does not receive. | PATH reuses watch's existing 1 Hz tick and only shows target RTT/loss, self/gateway context, rates and host transitions. No ARP/netem/forwarding/scenario claims. |
| Watch MAP | `cmd/gnulte-watch/view.go` already has gateway/self/device cards and a 1 Hz busiest-edge pulse. | Extend those helpers into **screen 7 PATH** after `scrHistory`. screens 1–6 and MAP gating stay unchanged. |
| Handoff | `handoffIP` returns `""` for non-host screens. | Add `scrPath` explicitly. `⏎`/`g` on PATH must never launch a stale target. |
| Shared input | `internal/tui/screen.go` has a process-wide `sharedKeys`; do not create a fresh decoder or `bufio.Scanner` in a raw screen. | Keep the shared stream. Read one byte at a time so a menu cannot read ahead into the next screen, and add `tui.FlushPending()` for hub handoff. |
| Fallbacks and PTY | Piped hubs must still use `plainMenu`; watch keys 1–6 must stay put. | No renumbering, no new gating that hides screens 1–6. `gnulte-verify/pty17.py` must pass unchanged before new checks are added. |

Vocabulary: **Detailed** means extra UI controls; `advanced` means the command-echo JSON key only; **Technical options** means CLI flag groups. Do not use "advanced" as a UI mode in new copy.

---

## 1. GNULTE-HUB — contextual front door

The hub remains a launcher. It does no network work and needs no privileges. Each child still asks for root when it needs it.

### 1.1 Screen H1: What do you want to do?

A `tui.MenuWith` picker. Context lines are part of the alternate-screen frame, not scrollback text.

```
  GNULTE — what do you want to do?
  ─────────────────────────────────────────────────────────────────────────────
  Nothing starts until you choose. Tools run in this terminal and ask for root
  only when they need it.

  ▸ 1  Test a connection        pick a device, then shape its traffic
    2  Check this machine       is everything ready?
    3  Find devices             sweep the network
    4  See connected devices    saved inventory
    5  Watch live traffic       six-screen live monitor
    6  Wi-Fi tools              authorised deauth testing
    7  Open reports             list, merge and compare
    8  Read the safety rules    before you begin
    9  Quit                     start nothing

  Detailed controls are available on the next step. Direct values never require them.
  ↑/↓ choose   Enter run   number jump   q quit
```

**Exact strings**

| ID | String |
| --- | --- |
| H1.TITLE | `GNULTE — what do you want to do?` |
| H1.CONTEXT | `Nothing starts until you choose. Tools run in this terminal and ask for root only when they need it.` |
| H1.NOTE | `Detailed controls are available on the next step. Direct values never require them.` |
| H1.FOOT | `↑/↓ choose   Enter run   number jump   q quit` |

Row labels 1–9 are exactly the current `actions()` labels. Only `Detail` text changes. A missing binary still renders `not installed` in place of its detail. Immediate digits 1–9 remain, including 9 = Quit.

Non-TTY fallback: print H1.CONTEXT and H1.NOTE, then use the existing `plainMenu`. Invalid input prints `Please type a number from the list, or q.` EOF aborts with no launch.

### 1.2 Screen H2: Detailed controls?

A second `tui.MenuWith`, shown for actions 1–7 after H1. This replaces a bare yes/no about "advanced mode".

```
  Detailed controls?
  ─────────────────────────────────────────────────────────────────────────────

  ▸ 1  Standard               presets and direct values
    2  Detailed               extra session controls

  Detailed adds session controls. It does not hide direct value entry.
  ↑/↓ choose   Enter continue   number jump   Esc back
```

| ID | String |
| --- | --- |
| H2.TITLE | `Detailed controls?` |
| H2.1 | `Standard` / `presets and direct values` |
| H2.2 | `Detailed` / `extra session controls` |
| H2.HELP | `Detailed adds session controls. It does not hide direct value entry.` |
| H2.FOOT | `↑/↓ choose   Enter continue   number jump   Esc back` |

Mapping:

- `Standard` uses `hub_detailed = false` for this launch.
- `Detailed` uses `hub_detailed = true` and shows the extra session controls from the existing settings (`beeps`, `interval`, `echo commands in sessions`) before launch.
- The saved `hub_detailed` value (default `false`) preselects H2; the choice persists only via the settings editor.
- `advanced` is never written implicitly. Detailed toggles it only when the operator explicitly changes that row.

### 1.3 Screen H3: How slow should it feel? (shaping path)

For action 1, mirror `simpleProfileChoice()` locally with these exact rows. Choosing 5 is the direct-numeric path and is available in **Standard** mode.

```
  How slow should it feel?
  ─────────────────────────────────────────────────────────────────────────────

  ▸ 1  A little laggy          small stutter, still usable
    2  Video calls break up    choppy voice and picture
    3  Web pages crawl         slow browsing
    4  Almost offline          very hard to use
    5  Let me choose numbers   set exact values

  Presets set latency, jitter, loss, duplication, reorder and bandwidth.
  ↑/↓ choose   Enter continue   number jump   Esc back
```

Mapping is unchanged: `cellular`, `voip`, `web`, `extreme`, then direct numeric entry. The old `advanced` detail on row 5 becomes `set exact values`.

### 1.4 Screen H4: Direct numeric entry

Choosing `Let me choose numbers` opens a hub-local prompt with the same fields, defaults and messages as `paramsWizard`:

```
  Parameter Configuration:  Enter keeps current values.

  Latency (ms) [0]: 300
  Jitter (ms) [0]: 30
  Loss (%) [0]: 0
  Duplicate (%) [0]:
  Reorder (%)
  Bandwidth (kbps) [0]:
  Duration (s) [0]: 60
```

Keep `ignoring non-numeric value`, `ignoring non-numeric interval (kept <n>s)`, blank = keep default, and Ctrl-D = abort. Do not reuse the profile sub-prompt here; H3 already chose direct numbers.

Pass the collected values to `gnulte` as explicit flags (`--latency`, `--jitter`, `--loss`, `--duplicate`, `--reorder`, `--bandwidth`, `--duration`, `--interval`, `--no-sound`) plus `--from-hub`. Add `--from-hub` to `cmd/gnulte/main.go` solely to set the existing `simple` guard so the child does not open `paramsWizard` a second time. Preset choices pass `--profile <name>` instead. The child still performs target selection and all safety/root steps.

### 1.5 Other hub actions

| Choice | Next step |
| --- | --- |
| 1 Test a connection | H2, then H3/H4, then `gnulte` with the chosen flags |
| 2 Check this machine | H2, then run `gnulte-quicksum` |
| 3 Find devices | H2, then run `gnulte-scan` |
| 4 See connected devices | H2, then run `gnulte-inventory` |
| 5 Watch live traffic | H2, then run `gnulte-watch` (HOSTS, screen 1) |
| 6 Wi-Fi tools | H2, then run `gnulte-wifi` |
| 7 Open reports | H2, then run `gnulte-report` |
| 8 Read the safety rules | run `gnulte --docs`, no H2 |
| 9 Quit | print `Bye.` |

After a child exits, keep `Starting <binary>...`, `<binary> exited with status <n>.`, `Could not run <binary>: <error>`, and `Press Enter to return to the menu...` unchanged.

### 1.6 Input handoff

`internal/tui` must read one byte at a time into `pending` so a menu cannot consume the next process's keystrokes. `tui.FlushPending()` drops any partial escape sequence before a child launch. The hub calls it after each menu and before `pause()`. `pause()` stays a canonical-mode Enter prompt; it must not create another TUI reader.

Add a PTY check for "type fast, then Enter": a digit pressed immediately after Enter on H1 must not leak into the child or the pause prompt.

---

## 2. Shared settings editor

### 2.1 Information architecture

Keep one `editItem` list with `get`/`set`/`def` and the existing JSON keys. Present it as five pages using the exact category strings:

```
1  NETWORK & MONITOR   2  SCANLTE SCAN   3  TRAFFIC ENGINE   4  GNULTE-WIFI   5  TERMINAL & UI
```

New rows:

- `hub_detailed` under `TERMINAL & UI`: default `off`; preselects H2.
- `topology_animation` under `TERMINAL & UI`: default `on`; controls PATH motion.
- Existing `advanced` stays in `TRAFFIC ENGINE`; label changes to `echo commands in sessions`. Key, default and behaviour do not change.

Rows useful only in Detailed mode may carry a leading `+`; this changes visibility, never values. All numeric rows remain directly editable.

### 2.2 Main list strings

| ID | String |
| --- | --- |
| S1.TITLE | `GNULTE settings — v17` |
| S1.SUB | `Saved defaults for every tool. Enter a value directly; ←/→ steps by one.` |
| S1.PAGES | `1 NETWORK & MONITOR  2 SCANLTE SCAN  3 TRAFFIC ENGINE  4 GNULTE-WIFI  5 TERMINAL & UI` |
| S1.DIRTY | `[unsaved: <n>]` |
| S1.CHANGED | `* changed (default <value>)` |
| S1.FOOT | `↑↓ field · ←/→ step · Enter edit/toggle · 1-5 page · / find · c changed · s save · Esc save & exit · D discard` |
| S1.EDIT.FOOT | `<error or hint> · Enter accept · Esc cancel value` |
| S1.DISCARD.ASK | `Discard unsaved changes? y/N` |
| S1.SAVED | `Saved to <path>.` |
| S1.NOMATCH | `No settings match "<text>". Esc to clear.` |

Only the active page's rows are drawn. Arrows move within the page and stop at its ends. `g/G` move to the first/last row of the current page.

### 2.3 Keys and validation

Preserved: arrows, `←/→` jog, `Enter` edit/toggle, `g/G`, `r` reset row, `R` reset all, `q/Q` return, `Esc` save & exit.

Added: `1–5` page jump in navigation mode only; `/` filter; `c` changed-only; `s` save and stay; `D` discard and exit; `+/-` show/hide marked rows.

Digits while editing are ordinary value runes. Typed values are validated on Enter and held in edit mode on failure; out-of-range values are not silently clamped. Arrow jog still clamps and briefly shows `At minimum (1)` / `At maximum (256)`.

Validation strings:

```
Whole seconds, 1–60.
A number of milliseconds, 100–60000.
Whole number, 10–240.
Whole number, 1–256.
Kilobits per second, 0–1000000 (0 = off).
on or off.
At least one channel, comma-separated, e.g. 1,6,11.
Interface cannot be empty. Type auto to detect the default route.
```

Accuracy fixes: title `v17`; `wifi frames per burst` 1–256; `wifi delay between bursts (s)` 1–60; `advanced mode (echo commands)` becomes `echo commands in sessions`.

### 2.4 Discard API

`settings.Edit` returns `(Config, bool, error)`; the bool is `save`. `Esc` and `q/Q` return `true`; confirmed `D` returns `false`. Every caller skips `settings.Save` when `save` is false. `s` still saves immediately and remains in the editor. The editor shows `Saved to <path>.` after a successful save. No caller may write the file on discard.

---

## 3. Live dashboard — animated PATH

### 3.1 Placement

The animated topology is **screen 7 PATH** in `gnulte-watch`, appended after `scrHistory`.

- `scrPath` is appended to the mode constants; `screenLabel(scrPath)` returns `PATH`.
- Add `case scrPath:` to `buildView` only. `buildLines` has no screen switch and must stay a plain per-host transcript. Add a separate `pathTranscriptLine()` for non-TTY and report output.
- `pathLines` reuses `mapNodes`, `mapGrid` and edge-row formatting from the MAP helpers; it does not replace `mapLines`/screen 5.
- Key `7` selects PATH; `p` is an alias. Keys 1–6 keep their screens and letters.
- `handoffIP(scrPath, currentIP)` returns `""`; `buildView` clears `view.currentIP` for PATH.
- PATH is **not** gated on the capture socket. Rates show `rate — (no capture socket)` when unavailable. MAP's gate stays exactly as it is.
- `env.pulse` stays gated to `scrMap`; PATH uses its own tick counter.
- Gateway and self fields already exist in `watchEnv`; no monitor changes are needed.

### 3.2 Data contract

PATH may show only what watch already owns:

- each target's IP/name, up/down state, average RTT and loss from the ping sampler;
- this host's IP and interface;
- gateway IP and last gateway RTT;
- aggregate rates when the capture socket exists;
- existing `watchEvent` up/down transitions.

It must not show ARP redirect state, `tc netem` state, forwarding state, scenario phases, or invented event timestamps. If a value is unknown, show `—`. No percentages other than real loss. No "optimisation" language.

### 3.3 Screen D1: PATH frame

```
  LIVE LAN WATCH · wlan0 · 192.0.2.0/24 · PATH
  ─────────────────────────────────────────────────────────────────────────────
   TARGET(S)                    GNULTE · this host           ROUTER                    INTERNET
   ┌──────────────────┐         ┌──────────────────┐        ┌─────────────────┐        ┌──────────────┐
   │ ● phone          │         │ ◉ 192.0.2.5      │        │ ◇ 192.0.2.1     │        │ upstream     │
   │   192.0.2.10     │         │   iface wlan0    │        │   gateway       │        │ not probed   │
   │   RTT 412 ms     │         │   rate 1.4MB/s↓  │        │   RTT 8 ms      │        │              │
   └──────────────────┘         └──────────────────┘        └─────────────────┘        └──────────────┘

       probe                    gateway                    uplink
   ● ────────▸───────── ◉ ─────────▸────────────── ◇ ─────────▸───────────── ▭
      RTT 412 ms · loss 5%       last reply 8 ms            not probed

   EVENTS
   12:04:07  host 192.0.2.10 up
   12:04:15  host 192.0.2.11 down
   ─────────────────────────────────────────────────────────────────────────────
   p/7 PATH · 1-6 screens · handoff off · Esc HOSTS · q quit
```

With two or more targets, the target column stacks one card per target and the other three nodes are shared. `↑↓` moves the existing target selection; no new reader.

**Layout bands**

| Width | Behaviour |
| --- | --- |
| < 78 cols | Two-row nodes, no rate line, event log limited to 2 lines |
| 78–115 | Three-row nodes, event log 3 lines |
| ≥ 116 | Four-row nodes plus RTT/loss/rate columns, event log 4 lines |

Frame height is constant within a band. If the terminal is shorter than 18 rows, drop the event log first, then the rate line; never truncate a label mid-word.

**Exact labels**

| ID | String |
| --- | --- |
| D.TITLE | `LIVE LAN WATCH · <iface> · <subnet> · PATH` |
| D.N1 | `TARGET(S)` |
| D.N2 | `GNULTE · this host` |
| D.N3 | `ROUTER` |
| D.N4 | `INTERNET` |
| D.E1 | `probe` |
| D.E2 | `gateway` |
| D.E3 | `uplink` |
| D.NRATE | `rate — (no capture socket)` |
| D.NOEVENT | `no transitions this session` |
| D.FOOT | `p/7 PATH · 1-6 screens · handoff off · Esc HOSTS · q quit` |
| D.DOTKEY | `one dot = one probe sample` (help overlay only) |

### 3.4 Motion states

One tick is the watch's existing 1 Hz tick. One dot advances one cell per tick; at most three dots per edge. Paint through `Screen.Draw`/`DrawFrame` once per tick. No per-frame sleeps, blinking or secondary stdin reader.

| State | Trigger | Visual |
| --- | --- | --- |
| `waiting` | selected target has no successful reply | Nodes dim; edges dashed `┄`; no travelling dots |
| `probe` | ping sent | Dot moves target → GNULTE → router |
| `reply` | ping reply arrives | Dot returns router → GNULTE → target; RTT uses the watch's existing thresholds |
| `loss` | ping timeout | Dot stops at GNULTE, renders `✗`; no whole-frame flash |
| `change` | host up/down event | Event line appended; node state updates |
| `fallback` | reduced motion, non-TTY, or `topology_animation = off` | Static frame or plain line |

Events use timestamps from `watchEvent.when` and only these forms:

```
<time>  host <ip> up
<time>  host <ip> down
```

### 3.5 Reduced-motion and non-TTY fallback

Automatic when `!ux.TTY()`, `TERM=dumb`, `GNULTE_NO_ANIMATION=1`, or `topology_animation = off`.

Full-screen fallback is the D1 layout with static `───▸───` edges, no dots. Live numbers still update on the 1 Hz tick.

Non-TTY output is one line per tick, or one final line with `-q`:

```
target 192.0.2.10 → GNULTE 192.0.2.5 (wlan0) → router 192.0.2.1 → internet | RTT 412ms | loss 5%
```

No escape sequences, box drawing or carriage-return repaint. With no capture socket, append `rate — (no capture socket)`.

---

## 4. Key bindings and focus rules

| Surface | Keys |
| --- | --- |
| H1/H2/H3 | `tui.MenuWith`: `↑/↓`, `j/k`, `Enter`, `Esc`, `q`, immediate `1–9`. No text field or alias parser. |
| H4 / direct values | Plain prompts: type value, Enter accept, blank keeps default, Ctrl-D aborts. |
| Settings | Preserved arrows, `←/→`, `Enter`, `g/G`, `r/R`, `q/Q`, `Esc` save & exit. Added `1–5`, `/`, `c`, `s`, `D`, `+/-`. Digits while editing are value runes. |
| Watch | 1 HOSTS, 2 TALKERS, 3 FLOWS, 4 ARP, 5 MAP, 6 HISTORY, **7 PATH** (`p` alias). `Esc` from PATH returns to HOSTS. Handoff disabled on PATH. `a` remains alarm-only. |
| Global | `Ctrl-C` runs registered cleanups. No mouse bindings. |

All raw-screen input goes through the shared `Screen.Key()`/`Poll()` stream.

---

## 5. First working pass vs deferred

### First working pass

1. **Hub**: H1 context, H2 Detailed controls, H3/H4 shaping flow, `--from-hub` flag, menu options and single-byte key handoff.
2. **Settings**: five pages, exact strings, filter, changed-only, explicit save/discard API, non-silent validation, two new defaulted keys, no stale help text.
3. **Watch PATH**: `scrPath` after `scrHistory`, `screenLabel` `PATH`, PATH helpers, key `7`/`p`, handoff disabled, 1 Hz probe motion from existing samples, reduced-motion and non-TTY fallbacks.
4. **Compatibility**: `plainMenu`, immediate numeric shortcuts, monitor's legacy reader and `gnulte-verify/pty17.py` still pass before new checks are added.

### Deferred

- Free-text intent aliases and inline values behind a `/` prompt.
- Passing arbitrary `--flag value` strings through the hub.
- Scenario, per-target and profile authoring UI.
- In-screen animation toggle on PATH; use settings/env in this pass.
- Merging PATH into MAP or renumbering any watch screen.
- Mouse support, new colour themes, sound cues or config migration beyond two defaulted keys.

---

## 6. Acceptance checks

1. **Existing harness first.** `python3 gnulte-verify/pty17.py` passes unchanged. It covers screens 2–5, handoffs, stale-IP regression and MAP no-launch gating; add separate checks for HOSTS, HISTORY and PATH rather than claiming it covers all six.
2. **Hub context and numbers.** H1 shows the exact title, context and note. Press `3` → `gnulte-scan` without Enter. Press `9` → `Bye.`
3. **Detailed controls.** Choose `1`, Enter → H2. Press `2` → Detailed; help says direct values are unaffected. `Esc` returns to H1.
4. **Direct numbers in Standard.** Choose `1`, `1` Standard, `1` "A little laggy" → `gnulte --profile cellular`; choose row 5 → direct prompts; `300` and `60` are accepted. Child does not open `paramsWizard` again.
5. **Config keys.** Settings `echo commands in sessions` toggles `advanced`; `Detailed controls in hub` toggles `hub_detailed`. No other key is renamed.
6. **Settings pages.** Title is `v17`, page tabs show the five original category names, `2` jumps pages only outside edit mode, `2` inside `ping timeout (ms)` is a value and is rejected with `A number of milliseconds, 100–60000.` `s` shows `Saved to <path>.`; confirmed `D` exits without touching the file.
7. **PATH screen.** In `gnulte-watch`, `7` and `p` show PATH. `1` → HOSTS, `5` → MAP, `6` → HISTORY. On PATH, `⏎`/`g` print no `gnulte -t ...`; `Esc` returns to HOSTS.
8. **PATH data.** Dots follow real ping/reply/loss results; events are existing up/down transitions only. With no capture socket, `rate — (no capture socket)` is shown and the frame still renders.
9. **Reduced motion / no TTY.** `GNULTE_NO_ANIMATION=1` gives static edges. Piped output contains only the plain line with no ESC sequences.
10. **Terminal restored.** After `q` or Ctrl-C, the prompt is back in the primary buffer with echo on and no alternate-buffer residue.

Record actual harness commands, dates and pass/fail here after implementation; the design itself is not validation evidence.
