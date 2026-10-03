// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"gnulte-go/internal/monitor"
)

// writeSessionReport renders a single self-contained HTML file combining the
// target statistics (SVG latency charts) with the full live console log — the
// entire history of the session, not just a summary.
func writeSessionReport(path string, log []string, res []monitor.Result, start, end time.Time) error {
	if err := os.WriteFile(path, []byte(sessionHTML(log, res, start, end)), 0o644); err != nil {
		return err
	}
	chownToInvoker(path)
	return nil
}

// cssReport is the shared stylesheet for the session report: dark, wide,
// print-friendly, and readable without JavaScript.
const cssReport = `<style>
:root{--bg:#0d1117;--panel:#151b24;--panel2:#1b2330;--edge:#2a3142;
 --text:#d8dee9;--dim:#8b96a8;--accent:#62a0ea;--ok:#57ab5a;--warn:#e5c07b;
 --bad:#e06c6c}
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
 background:var(--bg);color:var(--text);margin:0;padding:2rem 1.25rem;line-height:1.5}
main,.wrap{max-width:1020px;margin:0 auto}
.brand{font-size:1.6rem;font-weight:700;color:var(--accent);letter-spacing:.06em}
.tagline{color:var(--dim);margin-top:.15rem}
.meta{display:flex;flex-wrap:wrap;gap:.5rem;align-items:center;margin:1.2rem 0}
.chip{background:var(--panel);border:1px solid var(--edge);border-radius:999px;
 padding:.3rem .85rem;font-size:.85rem;color:var(--dim)}
.chip b{color:var(--text)}
.legal{color:#5b6472;font-size:.8rem;margin:.6rem 0 0;width:100%}
section{margin:1.8rem 0}
h2{color:var(--accent);font-size:1.1rem;border-bottom:1px solid var(--edge);
 padding-bottom:.4rem;letter-spacing:.02em}
table{border-collapse:collapse;width:100%;font-size:.9rem;margin:.6rem 0}
th,td{border:1px solid var(--edge);padding:.45rem .7rem;text-align:left}
th{background:var(--panel);color:var(--accent);text-transform:uppercase;
 font-size:.72rem;letter-spacing:.06em}
tr:nth-child(even) td{background:var(--panel2)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.pill{display:inline-block;border-radius:999px;padding:.1rem .65rem;
 font-size:.75rem;font-weight:600;letter-spacing:.03em}
.pill.up{background:#12401c;color:var(--ok);border:1px solid #2a6b33}
.pill.deg{background:#443717;color:var(--warn);border:1px solid #6b5424}
.pill.bad{background:#4a1d1d;color:var(--bad);border:1px solid #7a2f2f}
.pill.na{background:#232a36;color:var(--dim);border:1px solid var(--edge)}
.card{background:var(--panel);border:1px solid var(--edge);border-radius:10px;
 padding:1rem 1.1rem;margin:1.1rem 0}
.card h3{display:flex;align-items:center;gap:.6rem;margin:0 0 .6rem;font-size:1rem}
.card h3 .mono{font-size:.95rem;color:var(--accent)}
.chartwrap{overflow-x:auto}
.chartwrap svg{display:block;min-width:560px}
.stats{display:flex;flex-wrap:wrap;gap:.6rem 1.6rem;margin-top:.7rem;
 font-size:.85rem;color:var(--dim);border-top:1px solid var(--edge);padding-top:.7rem}
.stats b{color:var(--text);font-family:ui-monospace,Menlo,Consolas,monospace}
.empty{color:var(--dim);font-style:italic}
pre{background:#0a0e14;border:1px solid var(--edge);border-radius:8px;
 padding:1rem;overflow-x:auto;white-space:pre-wrap;word-break:break-word;
 font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.85rem}
.foot{color:#5b6472;margin-top:2.5rem;font-size:.8rem;border-top:1px solid var(--edge);padding-top:1rem}
</style>`

// targetStat is the per-target headline set, computed from raw counters so the
// report does not depend on unexported monitor helpers.
type targetStat struct {
	att, drops         int
	min, max, avg, p95 int64
	loss               float64
	hasData            bool
}

func collectStat(st monitor.Stats) targetStat {
	ts := targetStat{att: st.Count + st.Drops, drops: st.Drops}
	switch {
	case st.Count == 0 && st.Drops == 0:
		ts.hasData = false
	case st.Count == 0:
		ts.hasData = true
		ts.loss = 100
	default:
		ts.hasData = true
		ts.min, ts.max = st.Min, st.Max
		ts.avg = st.Total / int64(st.Count)
		ts.p95 = p95Of(st.Samples)
		ts.loss = float64(st.Drops) * 100 / float64(ts.att)
	}
	return ts
}

func (ts targetStat) pill() string {
	switch {
	case !ts.hasData:
		return `<span class="pill na">NO DATA</span>`
	case ts.loss >= 20:
		return `<span class="pill bad">UNSTABLE</span>`
	case ts.loss > 0:
		return `<span class="pill deg">DEGRADED</span>`
	default:
		return `<span class="pill up">UP</span>`
	}
}

func ms(v int64) string {
	if v <= 0 {
		return "&ndash;"
	}
	return fmt.Sprintf("%dms", v)
}

func pct(f float64) string {
	return fmt.Sprintf("%.0f%%", f)
}

// ipLess orders two IPv4 strings numerically so 192.168.1.2 precedes
// 192.168.1.10 (byte-wise string order would not).
func ipLess(a, b string) bool {
	aa, bb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(aa) && i < len(bb); i++ {
		na, nb := 0, 0
		fmt.Sscanf(aa[i], "%d", &na)
		fmt.Sscanf(bb[i], "%d", &nb)
		if na != nb {
			return na < nb
		}
	}
	return len(aa) < len(bb)
}

func sessionHTML(log []string, res []monitor.Result, start, end time.Time) string {
	dur := ""
	if !end.IsZero() {
		dur = fmt.Sprintf("%.0f s", end.Sub(start).Seconds())
	}
	title := "GNULTE session report"
	if len(res) > 0 {
		title = fmt.Sprintf("%s — %d target(s)", title, len(res))
	}

	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8">`)
	b.WriteString(`<meta name="viewport" content="width=device-width, initial-scale=1">`)
	b.WriteString("<title>" + htmlEscape(title) + "</title>")
	b.WriteString(cssReport)
	b.WriteString(`</head><body><div class="wrap">`)

	b.WriteString(`<div class="brand">GNULTE</div>`)
	b.WriteString(`<div class="tagline">Network Test Report — per-target latency, loss and the full command history</div>`)
	b.WriteString(`<section class="meta">` + "\n")
	b.WriteString(`<span class="chip">start <b>` + start.Format("2006-01-02 15:04:05") + `</b></span>` + "\n")
	if dur != "" {
		b.WriteString(`<span class="chip">duration <b>` + dur + `</b></span>` + "\n")
	}
	if len(res) > 0 {
		b.WriteString(fmt.Sprintf(`<span class="chip">targets <b>%d</b></span>`+"\n", len(res)))
	}
	b.WriteString(`<span class="chip">generated by <b>gnulte v` + version + `</b></span>` + "\n")
	b.WriteString(`<p class="legal">authorized network testing only · Neptune Productions · connectivity probed via ICMP echo with TCP-connect fallback on filtered targets</p>`)
	b.WriteString(`</section>` + "\n")

	if len(res) > 0 {
		b.WriteString(sessionSummaryHTML(Summarize(res)))
	}

	if len(res) == 0 {
		b.WriteString(`<p class="empty">No target statistics captured — the session was too short, or every probe timed out.</p>` + "\n")
	} else {
		// Heads-up table, one row per target, sorted by IP for scanning eyes.
		order := make([]int, len(res))
		for i := range order {
			order[i] = i
		}
		sort.SliceStable(order, func(a, b int) bool {
			return ipLess(res[order[a]].IP, res[order[b]].IP)
		})
		b.WriteString("<section><h2>Target summary</h2>\n<table>\n<thead>\n")
		b.WriteString(`<tr><th>#</th><th>Target</th><th>Samples</th><th>Min</th><th>Avg</th><th>P95</th><th>Max</th><th>Loss</th><th>Status</th></tr>` + "\n</thead><tbody>\n")
		for i, idx := range order {
			r := res[idx]
			ts := collectStat(r.Stats)
			txt := fmt.Sprintf("<tr><td>%d</td><td class=\"mono\">%s</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
				i+1, htmlEscape(r.IP), ts.att, ms(ts.min), ms(ts.avg), ms(ts.p95), ms(ts.max), pct(ts.loss), ts.pill())
			b.WriteString(txt)
		}
		b.WriteString(`</tbody></table></section>` + "\n")

		// One card per target: SVG latency timeline + headline numbers.
		for _, r := range res {
			b.WriteString(targetCard(r))
		}
	}

	b.WriteString(`<section><h2>Full log history</h2>` + "\n")
	if len(log) == 0 {
		b.WriteString(`<p class="empty">no console log captured (quiet run).</p>` + "\n")
	} else {
		b.WriteString("<pre>\n")
		for _, l := range log {
			b.WriteString(htmlEscape(l))
			b.WriteString("\n")
		}
		b.WriteString("</pre>\n")
	}
	b.WriteString(`</section>` + "\n")

	b.WriteString(`<div class="foot">generated by GNULTE v` + version + ` — licensed under the GPLv3.</div>`)
	b.WriteString(`</div></body></html>` + "\n")
	return b.String()
}

// sessionSummaryHTML renders the whole-run rollup as a chips row.
func sessionSummaryHTML(s SessionSummary) string {
	var b strings.Builder
	b.WriteString(`<section><h2>Session summary</h2>` + "\n")
	b.WriteString(`<div class="stats">`)
	b.WriteString(fmt.Sprintf(`<span>targets <b>%d</b></span>`, s.Targets))
	b.WriteString(fmt.Sprintf(`<span>attempts <b>%d</b></span>`, s.Attempts))
	b.WriteString(fmt.Sprintf(`<span>lost <b>%d (%.1f%%)</b></span>`, s.Lost, s.LossPct))
	if s.Samples > 0 {
		b.WriteString(fmt.Sprintf(`<span>min <b>%dms</b></span>`, s.Min))
		b.WriteString(fmt.Sprintf(`<span>avg <b>%dms</b></span>`, s.Avg))
		b.WriteString(fmt.Sprintf(`<span>p95 <b>%dms</b></span>`, s.P95))
		b.WriteString(fmt.Sprintf(`<span>max <b>%dms</b></span>`, s.Max))
		b.WriteString(fmt.Sprintf(`<span>σ <b>%.1fms</b></span>`, s.StdDev))
	}
	b.WriteString(fmt.Sprintf(`<span>MOS <b>%.1f</b> <em>(rough)</em></span>`, s.MOS))
	if runs := s.lossRunText(); runs != "" {
		b.WriteString(fmt.Sprintf(`<span>loss runs <b>%s</b></span>`, htmlEscape(runs)))
	}
	b.WriteString(`</div>` + "\n</section>" + "\n")
	return b.String()
}

// targetCard renders one target's section: a status pill by its IP, the SVG
// latency timeline, and the headline statistics.
func targetCard(r monitor.Result) string {
	ts := collectStat(r.Stats)
	var b strings.Builder
	b.WriteString(`<section class="card">` + "\n")
	b.WriteString(`<h3><span class="mono">` + htmlEscape(r.IP) + `</span>` + ts.pill() + `</h3>` + "\n")
	b.WriteString(`<div class="chartwrap">` + svgChart(r.Stats.Samples) + `</div>` + "\n")
	b.WriteString(`<div class="stats">`)
	b.WriteString(fmt.Sprintf(`<span>samples <b>%d</b></span>`, ts.att))
	b.WriteString(fmt.Sprintf(`<span>min <b>%s</b></span>`, ms(ts.min)))
	b.WriteString(fmt.Sprintf(`<span>max <b>%s</b></span>`, ms(ts.max)))
	b.WriteString(fmt.Sprintf(`<span>avg <b>%s</b></span>`, ms(ts.avg)))
	b.WriteString(fmt.Sprintf(`<span>p95 <b>%s</b></span>`, ms(ts.p95)))
	b.WriteString(fmt.Sprintf(`<span>loss <b>%s</b></span>`, pct(ts.loss)))
	b.WriteString(`</div>` + "\n</section>" + "\n")
	return b.String()
}

// svgChart renders a latency timeline so the report is readable without any
// JavaScript: gridlines with ms labels, an area fill under the line, and a red
// marker wherever a probe timed out (negative samples).
func svgChart(samples []int) string {
	if len(samples) == 0 {
		return `<svg viewBox="0 0 800 160" role="img" aria-label="no latency samples"></svg>` + "\n"
	}
	if len(samples) == 1 {
		samples = append(samples, samples[0])
	}
	// Scale by the max healthy value; broken / timeout samples ride the floor.
	maxV := 100
	for _, v := range samples {
		if v > maxV {
			maxV = v
		}
	}
	const (
		W, H       = 800, 160
		padL, padR = 44, 12
		padT, padB = 14, 26
	)
	plotW := W - padL - padR
	plotH := H - padT - padB
	coord := func(i, v int) (int, int) {
		x := padL + i*plotW/(len(samples)-1)
		y := padT + int(float64(maxV-v)*float64(plotH)/float64(maxV))
		if v < 0 {
			y = padT + plotH // timeouts sit on the baseline
		}
		return x, y
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf(`<svg width="%d" height="%d" viewBox="0 0 %d %d" role="img" aria-label="latency timeline">`+"\n", W, H, W, H))
	b.WriteString(`<defs><linearGradient id="fill" x1="0" y1="0" x2="0" y2="1">`)
	b.WriteString(`<stop offset="0" stop-color="#62a0ea" stop-opacity="0.35"/>`)
	b.WriteString(`<stop offset="1" stop-color="#62a0ea" stop-opacity="0.02"/>`)
	b.WriteString(`</linearGradient></defs>` + "\n")

	// Horizontal gridlines + labels every 25% of the scale.
	for g := 0; g <= 4; g++ {
		y := padT + g*plotH/4
		val := maxV - maxV*g/4
		b.WriteString(fmt.Sprintf(`<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#2a3142" stroke-width="1"/>`+"\n", padL, y, W-padR, y))
		b.WriteString(fmt.Sprintf(`<text x="%d" y="%d" fill="#8b96a8" font-size="10" text-anchor="end">%dms</text>`+"\n", padL-6, y+3, val))
	}

	// Area + line through the healthy samples.
	var pts, area []string
	var floorIdx []int
	for i, v := range samples {
		x, y := coord(i, v)
		pts = append(pts, fmt.Sprintf("%d,%d", x, y))
		if v < 0 {
			floorIdx = append(floorIdx, i)
		}
	}
	area = append(area, fmt.Sprintf("%d,%d", padL, padT+plotH))
	area = append(area, pts...)
	area = append(area, fmt.Sprintf("%d,%d", W-padR, padT+plotH))
	b.WriteString(fmt.Sprintf(`<polygon points="%s" fill="url(#fill)"/>`+"\n", strings.Join(area, " ")))
	b.WriteString(fmt.Sprintf(`<polyline points="%s" fill="none" stroke="#62a0ea" stroke-width="2"/>`+"\n", strings.Join(pts, " ")))

	// Timeout markers (red diamonds on the baseline).
	for _, i := range floorIdx {
		x := padL + i*plotW/(len(samples)-1)
		y := padT + plotH
		b.WriteString(fmt.Sprintf(`<path d="M%d %d l4 5 l-4 5 l-4 -5 z" fill="#e06c6c"/>`+"\n", x, y))
	}

	// Footnotes: scale ceiling and sample span.
	b.WriteString(fmt.Sprintf(`<text x="%d" y="%d" fill="#8b96a8" font-size="10">max %dms</text>`+"\n", padL, H-6, maxV))
	b.WriteString(fmt.Sprintf(`<text x="%d" y="%d" fill="#8b96a8" font-size="10" text-anchor="end">%d sample(s)</text>`+"\n", W-padR, H-6, len(samples)))
	b.WriteString(`</svg>` + "\n")
	return b.String()
}

// chownToInvoker hands the path to the user that ran sudo, mirroring how the
// engine returns captured files.
func chownToInvoker(path string) {
	if os.Getuid() != 0 {
		return
	}
	uid, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
	if err1 == nil && err2 == nil {
		_ = os.Chown(path, uid, gid)
	}
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;")
	return r.Replace(s)
}
