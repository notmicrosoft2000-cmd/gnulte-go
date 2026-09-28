// GNULTE — network testing toolkit.
//
// Copyright (C) 2026 Neptune Productions.
// Licensed under the GNU GPL version 3.

package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"gnulte-go/internal/traffic"
)

// writeReport renders the whole-session HTML report and writes it to path.
func writeReport(path string, s *lanSession) error {
	return os.WriteFile(path, []byte(sessionHTML(s)), 0o644)
}

// sessionHTML builds the standalone, self-contained report: summary table,
// one card per watched host (identity, rate and latency sparklines, top
// conversations), a global top-talkers table, and the escaped console log.
func sessionHTML(s *lanSession) string {
	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">")
	b.WriteString(`<meta name="viewport" content="width=device-width, initial-scale=1">`)
	b.WriteString("<title>GNULTE-LAN report</title>")
	b.WriteString(cssReport)
	b.WriteString("</head><body>\n")

	dur := "–"
	if !s.end.IsZero() {
		dur = fmtDuration(s.end.Sub(s.start))
	}
	endTxt := "–"
	if !s.end.IsZero() {
		endTxt = s.end.Format("15:04:05")
	}
	fmt.Fprintf(&b, "<header><h1>GNULTE-LAN <span class=sub>watch report</span></h1>\n")
	fmt.Fprintf(&b, "<p class=meta>iface <b>%s</b>", htmlEscape(s.iface))
	if s.subnet != "" {
		fmt.Fprintf(&b, " · net <b>%s</b> (router excluded)", htmlEscape(s.subnet))
	}
	fmt.Fprintf(&b, " · %s → %s · <b>%d</b> host(s) · <b>%d</b> tick(s) · %s · %.1fs refresh</p></header>\n",
		htmlEscape(s.start.Format("2006-01-02 15:04:05")),
		htmlEscape(endTxt),
		len(s.hosts), s.ticks, dur, float64(s.iv))

	// Summary table, IP-sorted.
	ips := append([]string(nil), s.hosts...)
	sort.Slice(ips, func(i, j int) bool { return ipLess(ips[i], ips[j]) })
	var downTotal, upTotal int64
	for _, ip := range s.hosts {
		st := s.stats[ip]
		downTotal += st.totRX
		upTotal += st.totTX
	}
	fmt.Fprintf(&b, "<section><h2>Summary</h2>\n<table class=summary><tr><th>Device</th><th>Type</th><th>Vendor</th><th>Peak ↓</th><th>Peak ↑</th><th>Total ↓</th><th>Total ↑</th><th>Avg ping</th><th>Loss</th><th>Status</th></tr>\n")
	for _, ip := range ips {
		st := s.stats[ip]
		inf := s.info[ip]
		f := func(v string) string { return htmlEscape(v) }
		fmt.Fprintf(&b, "<tr><td class=device><b>%s</b>"+hostSmall(inf)+"</td><td>"+f(inf.Type)+"</td><td>"+f(inf.Vendor)+"</td>"+
			"<td class=num>%s</td><td class=num>%s</td><td class=num>%s</td><td class=num>%s</td>"+
			"<td class=num>%dms</td><td class=num>%.0f%%</td><td>%s</td></tr>\n",
			htmlEscape(ip), rateStr(bps(st.peakRX, s.iv)), rateStr(bps(st.peakTX, s.iv)),
			humanBytes(st.totRX), humanBytes(st.totTX),
			st.ping.avg(), st.ping.loss(), statusPill(st.ping))
	}
	fmt.Fprintf(&b, "<tr class=total><td colspan=3>Network totals</td><td class=num>—</td><td class=num>—</td>"+
		"<td class=num><b>%s</b></td><td class=num><b>%s</b></td><td colspan=3></td></tr>\n",
		humanBytes(downTotal), humanBytes(upTotal))
	b.WriteString("</table></section>\n")

	// Per-host cards.
	b.WriteString("<section><h2>Per-host detail</h2>\n")
	for _, ip := range ips {
		st := s.stats[ip]
		inf := s.info[ip]
		flows := hostFlows(ip, s.flows)
		fmt.Fprintf(&b, cardHTML(ip, inf, st, flows, s.iv))
	}
	b.WriteString("\n</section>\n")

	// Global top talkers.
	b.WriteString("<section><h2>Top conversations (whole session)</h2>\n")
	glob := append([]traffic.Flow{}, s.flows...)
	sort.Slice(glob, func(i, j int) bool { return glob[i].Total() > glob[j].Total() })
	if len(glob) == 0 {
		b.WriteString("<p class=dim>No conversations were captured (traffic counter unavailable or the link was quiet).</p>\n")
	} else {
		b.WriteString("<table class=summary><tr><th>Endpoint A</th><th>Endpoint B</th><th>Volume</th><th>Packets</th><th>Split</th></tr>\n")
		for _, f := range glob {
			fmt.Fprintf(&b, "<tr><td class=mono>%s</td><td class=mono>%s</td><td class=num><b>%s</b></td><td class=num>%d</td>"+
				"<td class=dim>↓ %s · ↑ %s</td></tr>\n",
				htmlEscape(f.A), htmlEscape(f.B), humanBytes(f.Total()), f.ABp+f.BAp,
				humanBytes(f.BA), humanBytes(f.AB))
		}
		b.WriteString("</table>\n")
	}
	b.WriteString("</section>\n")

	// Console log.
	if len(s.log) > 0 {
		b.WriteString("<section><h2>Console trace</h2>\n<pre class=log>")
		b.WriteString(htmlEscape(strings.Join(s.log, "\n")))
		b.WriteString("\n</pre></section>\n")
	}
	b.WriteString("<footer>GNULTE-LAN " + version + " · passive capture · GPLv3</footer>\n</body></html>\n")
	return b.String()
}

func cardHTML(ip string, inf hostInfo, st *hostStat, flows []traffic.Flow, iv int) string {
	var b strings.Builder
	lbl := ip
	if inf.Host != "" {
		lbl = inf.Host + " <span class=dim>(" + htmlEscape(ip) + ")</span>"
	}
	fmt.Fprintf(&b, "<div class=card><div class=card-head><h3>%s %s</h3>%s</div>\n",
		htmlEscape(lbl), typePill(inf.Type), statusPill(st.ping))
	var meta []string
	if inf.MAC != "" {
		meta = append(meta, "<b>MAC</b> "+htmlEscape(inf.MAC))
	}
	if inf.Vendor != "" {
		meta = append(meta, "<b>vendor</b> "+htmlEscape(inf.Vendor))
	}
	if len(meta) > 0 {
		fmt.Fprintf(&b, "<div class=tags>%s</div>\n", strings.Join(meta, " · "))
	}
	fmt.Fprintf(&b, "<div class=stat-row><div class=stat><span>peak ↓</span><b>%s</b></div>"+
		"<div class=stat><span>peak ↑</span><b>%s</b></div>"+
		"<div class=stat><span>total ↓/↑</span><b>%s / %s</b></div>"+
		"<div class=stat><span>latency</span><b>avg %dms · max %dms</b></div>"+
		"<div class=stat><span>loss</span><b>%.0f%%</b></div></div>\n",
		rateStr(bps(st.peakRX, iv)), rateStr(bps(st.peakTX, iv)),
		humanBytes(st.totRX), humanBytes(st.totTX),
		st.ping.avg(), st.ping.max, st.ping.loss())
	if len(st.rxHist) > 1 || len(st.txHist) > 1 {
		b.WriteString("<div class=sparks>")
		b.WriteString("<div><span class=dim>down</span>" + sparkSVG(st.rxHist, iv) + "</div>")
		b.WriteString("<div><span class=dim>up</span>" + sparkSVG(st.txHist, iv) + "</div>")
		b.WriteString("</div>\n")
	}
	if len(st.ping.samples) > 0 {
		b.WriteString("<div class=sparks><div><span class=dim>latency</span>" + pingSpark(st.ping.samples) + "</div></div>\n")
	}
	if len(flows) > 0 {
		fmt.Fprintf(&b, "<div class=conversations><h4>Top conversations</h4>")
		for _, f := range flows {
			// Flow endpoints relative to this host: down = toward it.
			down, up := f.BA, f.AB
			if endpointHost(f.A) == ip {
				down, up = f.AB, f.BA
			}
			peer := f.A
			if endpointHost(f.A) == ip {
				peer = f.B
			}
			fmt.Fprintf(&b, "<div class=conv><span class=mono>%s</span>"+
				"<span class=num><b>%s</b></span><span class=dim>↓ %s · ↑ %s</span></div>\n",
				htmlEscape(peer), humanBytes(f.Total()), humanBytes(down), humanBytes(up))
		}
		b.WriteString("</div>\n")
	}
	b.WriteString("</div>\n")
	return b.String()
}

// hostFlows returns the session's conversations touching one host, biggest
// first, capped at five.
func hostFlows(ip string, flows []traffic.Flow) []traffic.Flow {
	var out []traffic.Flow
	for _, f := range flows {
		if endpointHost(f.A) == ip || endpointHost(f.B) == ip {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Total() > out[j].Total() })
	if len(out) > 5 {
		out = out[:5]
	}
	return out
}

// endpointHost splits an "ip:port" endpoint back to its bare IP.
func endpointHost(e string) string {
	if i := strings.LastIndexByte(e, ':'); i >= 0 {
		return e[:i]
	}
	return e
}

// statusPill labels a host by its loss ratio: UP, DEGRADED, UNSTABLE or
// SILENT when we never got an answer.
func statusPill(h pinger) string {
	var cls, txt string
	switch {
	case h.count+h.drops == 0:
		cls, txt = "s", "SILENT"
	case h.loss() == 0:
		cls, txt = "u", "UP"
	case h.loss() < 30:
		cls, txt = "d", "DEGRADED"
	default:
		cls, txt = "x", "UNSTABLE"
	}
	return fmt.Sprintf("<span class=\"pill %s\">%s</span>", cls, txt)
}

func typePill(t string) string {
	if t == "" {
		return ""
	}
	return fmt.Sprintf("<span class=\"pill t\">%s</span>", htmlEscape(t))
}

func hostSmall(inf hostInfo) string {
	if inf.Host == "" {
		return ""
	}
	return fmt.Sprintf("<span class=dim> · %s</span>", htmlEscape(inf.Host))
}

// sparkSVG renders a per-tick byte-rate history as a filled area line.
func sparkSVG(samples []int64, iv int) string {
	const w = 320
	const h = 44
	if len(samples) == 0 {
		return fmt.Sprintf(`<svg class=spark viewBox="0 0 %d %d"><text x="4" y="24" class=dimtxt>no samples</text></svg>`, w, h)
	}
	// Peak for scaling, in bytes/s so the axis label reads naturally.
	var peak int64
	for _, v := range samples {
		if bps := bps(v, iv); bps > peak {
			peak = bps
		}
	}
	if peak == 0 {
		return fmt.Sprintf(`<svg class=spark viewBox="0 0 %d %d"><text x="4" y="24" class=dimtxt>idle</text></svg>`, w, h)
	}
	points := make([]string, len(samples))
	steps := float64(len(samples) - 1)
	for i, v := range samples {
		x := 0.0
		if steps > 0 {
			x = float64(i) * w / steps
		}
		y := h - float64(bps(v, iv))*h/float64(peak)
		points[i] = fmt.Sprintf("%.1f,%.1f", x, y)
	}
	area := "0," + strconv.Itoa(h) + " " + strings.Join(points, " ") + " " + fmt.Sprintf("%.1f,%d", float64(w), h)
	return fmt.Sprintf(`<svg class=spark viewBox="0 0 %d %d"><polygon points="%s" fill="var(--ink2)"/><polyline points="%s" fill="none" stroke="var(--accent)" stroke-width="1.6"/><text x="4" y="12" class=dimtxt>peak %s</text></svg>`,
		w, h, area, strings.Join(points, " "), rateStr(peak))
}

// pingSpark renders the latency history as a same-style sparkline (ms).
func pingSpark(samples []int) string {
	const w = 320
	const h = 44
	var peak int
	for _, v := range samples {
		if v > peak {
			peak = v
		}
	}
	if peak == 0 {
		peak = 1
	}
	points := make([]string, len(samples))
	steps := float64(len(samples) - 1)
	for i, v := range samples {
		x := 0.0
		if steps > 0 {
			x = float64(i) * w / steps
		}
		y := h - float64(v)*h/float64(peak)
		points[i] = fmt.Sprintf("%.1f,%.1f", x, y)
	}
	return fmt.Sprintf(`<svg class=spark viewBox="0 0 %d %d"><polyline points="%s" fill="none" stroke="var(--lat)" stroke-width="1.6"/></svg>`, w, h, strings.Join(points, " "))
}

// bpsOf-style helpers live inline via bps(); rateStr formats a bytes/second
// figure for table and card cells ("–" when the link stayed quiet).
func rateStr(bps int64) string {
	if bps <= 0 {
		return "–"
	}
	return humanRate(bps)
}

// humanBytes formats a byte count as the largest comfortable unit.
func humanBytes(n int64) string {
	switch {
	case n >= 1<<40:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<40))
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// humanRate formats bytes/second ("1.2MB/s"); the tiny helpers the stream
// tool already owns live in ux, but keeping the report self-contained lets
// the numbers read identically on any machine.
func humanRate(b int64) string {
	switch {
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB/s", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB/s", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%d B/s", b)
	}
}

func fmtDuration(d time.Duration) string {
	if d < time.Second {
		return d.Round(time.Millisecond).String()
	}
	return d.Round(time.Second).String()
}

func htmlEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&#39;",
	)
	return r.Replace(s)
}

// ipLess orders dotted IPv4 quads numerically ("10.2.1.1" < "10.10.0.1").
func ipLess(a, b string) bool {
	ap := strings.Split(a, ".")
	bp := strings.Split(b, ".")
	for i := 0; i < 4; i++ {
		if i >= len(ap) || i >= len(bp) {
			return len(ap) < len(bp)
		}
		ai, _ := strconv.Atoi(ap[i])
		bi, _ := strconv.Atoi(bp[i])
		if ai != bi {
			return ai < bi
		}
	}
	return false
}

// cssReport is the standalone dark stylesheet for the watch report.
const cssReport = `<style>
:root{--bg:#0d1117;--card:#161b22;--ink:#c9d1d9;--ink2:#2f6f4a;--dim:#8b949e;--line:#21262d;--accent:#58a6ff;--up:#3fb950;--deg:#d29922;--bad:#f85149;--lat:#d2a8ff}
*{box-sizing:border-box}body{background:var(--bg);color:var(--ink);font:14px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;margin:0;padding:24px;max-width:1100px;margin:0 auto}
h1{font-size:22px;margin:0 0 4px}h1 .sub{color:var(--dim);font-weight:500}h2{font-size:16px;margin:28px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px}h3{margin:0;font-size:15px}h4{margin:6px 0;font-size:12px;color:var(--dim);text-transform:uppercase;letter-spacing:.4px}
header .meta{color:var(--dim);font-size:13px;margin:0}
.dim{color:var(--dim)}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}
.pill{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;font-weight:600;vertical-align:middle}
.pill.u{background:rgba(63,185,80,.15);color:var(--up)}.pill.d{background:rgba(210,153,34,.15);color:var(--deg)}.pill.x{background:rgba(248,81,73,.18);color:var(--bad)}.pill.s{background:rgba(139,148,158,.15);color:var(--dim)}.pill.t{background:rgba(88,166,255,.12);color:var(--accent)}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;color:var(--dim);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.4px;padding:6px 8px;border-bottom:1px solid var(--line)}
td{padding:6px 8px;border-bottom:1px solid var(--line)}td.num{text-align:right;font-variant-numeric:tabular-nums}.device b{display:inline-block}
tr.total td{color:var(--dim);border-top:2px solid var(--line)}tr.total b{color:var(--ink)}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:12px 0}
.card-head{display:flex;align-items:center;gap:8px}
.tags{color:var(--dim);font-size:12px;margin-top:6px}
.stat-row{display:flex;flex-wrap:wrap;gap:18px;margin-top:10px}.stat span{display:block;color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:.4px}.stat b{font-size:13px}
.sparks{display:flex;flex-wrap:wrap;gap:14px;margin-top:10px}.sparks>div{min-width:320px}
.sparks .dim{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.4px;margin-bottom:2px}
svg.spark{display:block;width:100%;max-width:320px;height:44px;background:#0a0e14;border-radius:6px;border:1px solid var(--line)}
.dimtxt{fill:var(--dim);font-size:10px}
.conversations{margin-top:10px}
.conv{display:flex;gap:14px;padding:3px 0;border-top:1px dashed var(--line);font-size:12.5px}.conv .mono{flex:1}
pre.log{background:#0a0e14;border:1px solid var(--line);border-radius:8px;padding:12px;overflow-x:auto;font-size:11.5px;line-height:1.45}
footer{margin-top:32px;color:var(--dim);font-size:12px;text-align:center}
</style>`
