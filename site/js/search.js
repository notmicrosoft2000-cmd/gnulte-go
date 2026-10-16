/* GNULTE site search — filters the documentation index in the browser.
   No dependencies. The index below lists every page of the site. */

var SEARCH_INDEX = [
  { u: "index.html", t: "GNULTE — Home", k: "home gnulte gnu lan network testing environment suite introduction news release",
    d: "GNULTE is a suite of focused Linux tools for testing, inspecting and troubleshooting networks you own or are authorised to test." },
  { u: "tools.html", t: "Tool directory", k: "tools suite gnulte-lan gnulte-scan gnulte-devices gnulte-wifi gnulte-doctor gnulte-trace gnulte-top directory",
    d: "The eight tools of the suite: shaping, LAN watch, scanning, inventory, Wi-Fi, doctor, trace and top." },
  { u: "docs.html", t: "Documentation", k: "documentation manual index docs guide",
    d: "Index of the GNULTE manual: installation, configuration, usage, command reference, troubleshooting and FAQ." },
  { u: "downloads.html", t: "Downloads", k: "download source tarball git clone install build release",
    d: "GNULTE is distributed as source. Build with Go 1.21+ using build.sh; install with install.sh." },
  { u: "changelog.html", t: "Changelog", k: "changelog release history versions news 16.13 16.12 unpluged unplugged",
    d: "Every release of the Go edition, newest first: v16.13 down to v15.0, plus the v17 Unplugged programme." },
  { u: "about.html", t: "About GNULTE", k: "about philosophy contributors license gpl safety authorised authorized contact neptune productions",
    d: "What GNULTE is, how it is developed, licensing, authorised-use policy and how to get in touch." },
  { u: "search.html", t: "Search", k: "search find documentation",
    d: "Search the GNULTE site." },
  { u: "docs/install.html", t: "Installation", k: "install installation requirements build.sh install.sh uninstall go iproute2 iptables iputils root",
    d: "Requirements, build from source, install to /usr/local/bin, update and uninstall." },
  { u: "docs/configuration.html", t: "Configuration", k: "configuration settings profiles scenario per-target config.json devices.json state files",
    d: "Saved defaults, the twelve built-in impairment profiles, scenario scripts and per-target overrides." },
  { u: "docs/usage.html", t: "Usage", k: "usage quick start examples recipes hand-off gnulte-lan screens keys workflow",
    d: "Common workflows: shape a host, watch the LAN, scan, inventory, and the hand-off from watch to test." },
  { u: "docs/troubleshooting.html", t: "Troubleshooting", k: "troubleshooting problems doctor ip_forward netem module icmp filtered capture permission denied",
    d: "Run gnulte-doctor first; fixes for privileges, tc/iptables, ip_forward, kernel modules and filtered ICMP." },
  { u: "docs/faq.html", t: "FAQ", k: "faq frequently asked questions windows macos linux platform root external tools tcpdump arping",
    d: "Platform support, root requirements, external tools, data locations and safety records." },
  { u: "docs/gnulte.html", t: "gnulte — command reference", k: "gnulte command reference latency jitter loss duplicate reorder bandwidth netem shaping arpspoof target",
    d: "The core shaping engine: ARP-spoofed routing into tc netem with a live dashboard and HTML report." },
  { u: "docs/gnulte-lan.html", t: "gnulte-lan — command reference", k: "gnulte-lan watch hosts talkers flows neighbours map history json export alarm",
    d: "The live LAN watch: six screens of hosts, talkers, flows, ARP neighbours, interconnection map and history." },
  { u: "docs/gnulte-scan.html", t: "gnulte-scan — command reference", k: "gnulte-scan sweep port scan deep os fingerprint oui vendor watch interactive json yaml csv",
    d: "Parallel sweep with an in-Go deep port scanner, OUI vendors, OS fingerprinting and live re-scanning." },
  { u: "docs/gnulte-devices.html", t: "gnulte-devices — command reference", k: "gnulte-devices inventory arp neighbours vendor mdns hostname html report csv json yaml",
    d: "Instant ARP/neighbour inventory with vendors, mDNS names and type guesses. No root." },
  { u: "docs/gnulte-wifi.html", t: "gnulte-wifi — command reference", k: "gnulte-wifi deauth deauthentication 802.11 monitor mode channel jitter reason burst",
    d: "Targeted 802.11 deauthentication for authorised Wi-Fi disassociation testing." },
  { u: "docs/gnulte-doctor.html", t: "gnulte-doctor — command reference", k: "gnulte-doctor health check pre-flight pass warn fail json exit privileges modules route",
    d: "Zero-dependency pre-flight check: privileges, tc/iptables, ip_forward, kernel modules, routes and duplicate IPs." },
  { u: "docs/gnulte-trace.html", t: "gnulte-trace — command reference", k: "gnulte-trace mtr traceroute hop ttl icmp echo path loss html report",
    d: "In-process mtr-style hop-by-hop path probe with per-hop loss and an HTML report." },
  { u: "docs/gnulte-top.html", t: "gnulte-top — command reference", k: "gnulte-top bandwidth talkers flows af_packet rates csv json sampling",
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
    var term = terms[i];
    if (hay.indexOf(term) === -1) return 0;   /* every term must appear */
    score += entry.t.toLowerCase().indexOf(term) !== -1 ? 3 : 1;
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

  var terms = query.toLowerCase().split(/\s+/);
  var hits = [];
  for (var i = 0; i < SEARCH_INDEX.length; i++) {
    var s = searchScore(SEARCH_INDEX[i], terms);
    if (s > 0) hits.push({ e: SEARCH_INDEX[i], s: s });
  }
  hits.sort(function (a, b) { return b.s - a.s; });

  var html = "<p><b>" + hits.length + " result" + (hits.length === 1 ? "" : "s") +
             "</b> for &ldquo;" + searchEscape(query) + "&rdquo;</p>";
  if (hits.length === 0) {
    html += "<p>No page matched every search term. Try fewer words, or browse " +
            '<a href="docs.html">the documentation index</a>.</p>';
  } else {
    html += '<table class="data"><tr><th style="width:30%">Page</th><th>Summary</th></tr>';
    for (var j = 0; j < hits.length; j++) {
      html += '<tr><td><a href="' + hits[j].e.u + '">' + searchEscape(hits[j].e.t) +
              '</a></td><td>' + searchEscape(hits[j].e.d) + "</td></tr>";
    }
    html += "</table>";
  }
  out.innerHTML = html;
}

if (window.addEventListener) window.addEventListener("DOMContentLoaded", searchRun, false);
