# GNULTE website

Static website for the GNULTE toolkit. No build step, no framework, no third-party
scripts — plain semantic HTML, one stylesheet and two small dependency-free scripts.
All links are relative, so the site works at a domain root or under a sub-path such as
`https://<user>.github.io/gnulte/`.

## Layout

```
site/
  index.html                homepage: interface preview and capability index
  tools.html                tool directory (eight executables)
  products.html             workstation architecture and topology diagram
  docs.html                 documentation index
  downloads.html            source install by distribution
  changelog.html            release history
  news.html                 release notes
  about.html                project, safety, license
  support.html              getting help
  contact.html              contact and reporting
  search.html               client-side documentation search
  feed.xml                  Atom release feed
  css/workstation.css       engineering-workstation stylesheet
  js/workstation.js         nav toggle, copy buttons, install tabs, topology
  js/search.js              search index and filtering
  fonts/                    self-hosted PT Sans (SIL OFL)
  img/                      logo and favicon set
  docs/                     manual
    gnulte-hub.html         launcher reference
    install.html
    configuration.html
    usage.html
    troubleshooting.html
    faq.html
    gnulte.html
    gnulte-watch.html
    gnulte-watch-trace.html
    gnulte-watch-top.html
    gnulte-scan.html
    gnulte-inventory.html
    gnulte-wifi.html
    gnulte-quicksum.html
    gnulte-report.html
```

## Design system

The site reads as an engineering workstation, not a product landing page. Surfaces are
near-black graphite, text is off-white, one desaturated green marks active state, amber
marks warnings, and red is reserved for actual security notice. Labels, tables and
commands use a monospace face; reading text uses a quiet system sans. PT Sans is used
only for display headings.

The layout uses hairline rules, numbered sections and tabular data. There are no
gradients, blur, glow, rounded cards, fake testimonials, marketing statistics or
decorative scroll effects. The hero window shows real `gnulte-inventory` output; the
host-context panel is explicitly labelled as read-only system context, not a GNULTE
security verdict.

Breakpoints: the manual's right rail drops at 1100 px, the hero stacks at 1040 px,
and the navigation collapses behind a `menu` toggle at 760 px. Print styles hide the
chrome and keep the manual readable on paper. Hover and focus states are short and
respect `prefers-reduced-motion`.

## Deploying

The published site lives in the separate `gnulte` repository, with GitHub Pages serving
its `docs/` directory. Mirror this directory into that checkout, preserving filenames:

```sh
rsync -a --delete site/ /path/to/gnulte/docs/
git -C /path/to/gnulte add docs
git -C /path/to/gnulte commit -m "site: ship the engineering-workstation redesign"
git -C /path/to/gnulte push
```

Any static host can serve the contents of `site/` directly. Do not point Pages at this
repository; the separate site repo is the publishing source.

## Updating content

- The version appears in the utility bar, release boxes and footer of every page. When
  the toolkit version changes, update it across `site/`.
- Keep `changelog.html`, `news.html` and `feed.xml` newest-first and dated.
- The search index is the `SEARCH_INDEX` array at the top of `js/search.js`; add an
  entry for every new page and keep eight-executable wording current.
- Command reference pages must match the binaries' real flags. Extract them with
  `<binary> -h` rather than writing them from memory.
- The interactive topology on `products.html` takes its detail text from
  `data-name`, `data-detail` and `data-command` on each SVG node.

## Icons

The inline mark in the header and footer is drawn in SVG so it follows the current
accent colour. The PNG files in `img/` remain the favicon and touch-icon set; regenerate
the full size range if the mark changes.
