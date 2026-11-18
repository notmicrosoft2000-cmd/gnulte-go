/* GNULTE site search: filters the page index in the browser.
   No dependencies. Keep the index in sync with the pages in site/. */

var SEARCH_INDEX = [
  { u: "index.html", t: "GNULTE", k: "home overview introduction suite lan network testing environment",
    d: "Seven Linux tools for shaping, watching and inspecting traffic on a network you own or are authorised to test." },
  { u: "tools.html", t: "Tool directory", k: "tools suite gnulte-watch gnulte-scan gnulte-inventory gnulte-wifi gnulte-quicksum gnulte-report gnulte-watch trace gnulte-watch top directory",
    d: "The seven GNULTE binaries: what each one does, what privileges it needs and how they fit together." },
  { u: "docs.html", t: "Documentation", k: "documentation manual index docs guide reference",
    d: "The GNULTE manual: installation, configuration, usage and one reference page per binary." },
  { u: "downloads.html", t: "Downloads", k: "download source tarball git clone install build release",
    d: "Source-only distribution. Clone the tree, build with Go 1.21+, install with install.sh." },
  { u: "changelog.html", t: "Changelog", k: "changelog release history versions 17.0 16.13 16.12 unplugged compare",
    d: "Every release of the Go edition, newest first, plus the Unplugged programme." },
  { u: "about.html", t: "About GNULTE", k: "about philosophy contributors license gpl safety authorised authorized neptune productions",
    d: "What GNULTE is, how it is developed, licensing, authorised use and where to send a patch." },
  { u: "products.html", t: "Suite architecture", k: "suite architecture scenarios chaos carrier iot qos netem proxy emulator",
    d: "The tools, where the shaping happens, and the problems the suite is built for." },
  { u: "news.html", t: "Field notes", k: "news notes milestones releases unplugged atom rss",
    d: "Milestones from development: recent releases and the Unplugged programme." },
  { u: "support.html", t: "Getting help", k: "support help doctor diagnostics troubleshooting faq issue tracker",
    d: "Run gnulte-quicksum, read the troubleshooting matrix, open an issue with a reproducible command." },
  { u: "contact.html", t: "Contact & reporting", k: "contact issue tracker patches security vulnerability report repository",
    d: "Bug reports, patches and security reports go through the public repository; there is no phone line." },
  { u: "search.html", t: "Search", k: "search find documentation",
    d: "Search the GNULTE site." },
  { u: "docs/install.html", t: "Installation", k: "install requirements build.sh install.sh uninstall go iproute2 iptables root",
    d: "Requirements, build from source, install to /usr/local/bin, update and uninstall." },
  { u: "docs/configuration.html", t: "Configuration", k: "configuration settings profiles scenario per-target config.json devices.json state files",
    d: "Saved defaults, the built-in impairment profiles, scenario scripts and per-target overrides." },
  { u: "docs/usage.html", t: "Usage", k: "usage quick start examples recipes hand-off gnulte-watch screens keys workflow",
    d: "Common workflows: shape a host, watch the LAN, scan, inventory, and the hand-off from watch to test." },
  { u: "docs/troubleshooting.html", t: "Troubleshooting", k: "troubleshooting problems doctor ip_forward netem module icmp filtered capture permission denied",
    d: "Run gnulte-quicksum first; fixes for privileges, tc/iptables, ip_forward, kernel modules and filtered ICMP." },
  { u: "docs/faq.html", t: "FAQ", k: "faq frequently asked questions windows macos linux platform root external tools tcpdump arping",
    d: "Platform support, root requirements, external tools, data locations and safety records." },
  { u: "docs/gnulte.html", t: "gnulte(8): command reference", k: "gnulte command reference latency jitter loss duplicate reorder bandwidth netem shaping spoof target",
    d: "The core shaping engine: ARP-redirected routing into tc netem with a live dashboard and HTML report." },
  { u: "docs/gnulte-report.html", t: "gnulte-report(8): command reference", k: "gnulte-report reports archive merge compare index snapshot dated folders json",
    d: "List and index saved reports, merge device exports, diff snapshots and file them into dated folders." },
  { u: "docs/gnulte-watch.html", t: "gnulte-watch(8): command reference", k: "gnulte-watch watch hosts talkers flows neighbours map history json export alarm",
    d: "The live LAN watch: six screens of hosts, talkers, flows, ARP neighbours, interconnection map and history." },
  { u: "docs/gnulte-scan.html", t: "gnulte-scan(8): command reference", k: "gnulte-scan sweep port scan deep os fingerprint oui vendor watch interactive json yaml csv",
    d: "Parallel sweep with an in-Go deep port scanner, OUI vendors, OS fingerprinting and live re-scanning." },
  { u: "docs/gnulte-inventory.html", t: "gnulte-inventory(8): command reference", k: "gnulte-inventory inventory arp neighbours vendor mdns hostname html report csv json yaml",
    d: "Instant ARP/neighbour inventory with vendors, mDNS names and type guesses. No root." },
  { u: "docs/gnulte-wifi.html", t: "gnulte-wifi(8): command reference", k: "gnulte-wifi deauth deauthentication 802.11 monitor mode channel jitter reason burst",
    d: "Targeted 802.11 deauthentication for authorised Wi-Fi disassociation testing." },
  { u: "docs/gnulte-quicksum.html", t: "gnulte-quicksum(8): command reference", k: "gnulte-quicksum health check pre-flight pass warn fail json exit privileges modules route",
    d: "Zero-dependency pre-flight check: privileges, tc/iptables, ip_forward, kernel modules, routes and duplicate IPs." },
  { u: "docs/gnulte-watch-trace.html", t: "gnulte-watch trace(8): command reference", k: "gnulte-watch trace mtr traceroute hop ttl icmp echo path loss html report",
    d: "In-process mtr-style hop-by-hop path probe with per-hop loss and an HTML report." },
  { u: "docs/gnulte-watch-top.html", t: "gnulte-watch top(8): command reference", k: "gnulte-watch top bandwidth talkers flows af_packet rates csv json sampling",
    d: "Live per-host and per-conversation bandwidth from an in-process AF_PACKET counter." }
];

function searchGetQuery() {
  var m = /[?&]q=([^&]*)/.exec(window.location.search);
  return m ? decodeURIComponent(m[1].replace(/\+/g, " ")) : "";
}

function searchScore(entry, terms) {
  var hay = (entry.t + " " + entry.k + " " + entry.d).toLowerCase();
  var score = 0;
  for (var i = 0; i < terms.length; i++) {
    if (hay.indexOf(terms[i]) === -1) return 0;
    score += entry.t.toLowerCase().indexOf(terms[i]) !== -1 ? 3 : 1;
  }
  return score;
}

function searchEscape(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function searchRun() {
  var input = document.getElementById("q");
  var out = document.getElementById("results");
  var query = searchGetQuery();
  if (input) input.value = query;
  if (!query || !out) return;

  var terms = query.toLowerCase().split(/\s+/).filter(Boolean);
  var hits = [];
  for (var i = 0; i < SEARCH_INDEX.length; i++) {
    var s = searchScore(SEARCH_INDEX[i], terms);
    if (s > 0) hits.push({ e: SEARCH_INDEX[i], s: s });
  }
  hits.sort(function (a, b) { return b.s - a.s; });

  var html = '<p><b>' + hits.length + ' result' + (hits.length === 1 ? "" : "s") +
             '</b> for “' + searchEscape(query) + '”</p>';
  if (hits.length === 0) {
    html += '<p>No page matched every term. Try fewer words, or browse ' +
            '<a href="docs.html">the documentation index</a>.</p>';
  } else {
    html += '<div class="table-wrap"><table class="data"><thead><tr><th>Page</th><th>Summary</th></tr></thead><tbody>';
    for (var j = 0; j < hits.length; j++) {
      html += '<tr><td><a href="' + hits[j].e.u + '">' + searchEscape(hits[j].e.t) +
              '</a></td><td>' + searchEscape(hits[j].e.d) + "</td></tr>";
    }
    html += "</tbody></table></div>";
  }
  out.innerHTML = html;
}

if (window.addEventListener) window.addEventListener("DOMContentLoaded", searchRun, false);
