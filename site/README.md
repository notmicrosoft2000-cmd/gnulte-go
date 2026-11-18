# GNULTE website

Static website for the GNULTE toolkit. No build step, no framework, no third-party
scripts — plain semantic HTML, one stylesheet, small dependency-free scripts.

## Layout

```
site/
  index.html            homepage
  tools.html            tool directory
  products.html         suite architecture
  docs.html             documentation index
  downloads.html        source downloads and install
  changelog.html        release history
  news.html             field notes
  about.html            project, safety, license
  support.html          getting help
  contact.html          contact and reporting
  search.html           client-side documentation search
  feed.xml              Atom field-notes feed
  docs/                 manual: install, configuration, usage, troubleshooting, faq
    gnulte.html         command reference, one page per binary
    gnulte-watch.html
    gnulte-scan.html
    gnulte-inventory.html
    gnulte-wifi.html
    gnulte-quicksum.html
    gnulte-watch-trace.html
    gnulte-watch-top.html
  css/gnulte.css        the field-manual stylesheet
  js/site.js            mobile nav toggle and terminal copy buttons
  js/search.js          search index + filtering
  fonts/                self-hosted PT Sans / PT Serif (SIL OFL)
  img/                  logo and favicon set (generated PNGs)
```

All links are relative, so the site works both at a domain root and under a
sub-path such as `https://<user>.github.io/gnulte/`.

## Deploying

The site is plain files; pick whichever fits the pages setup in use:

- **GitHub Pages, `gh-pages` branch:** `git subtree push --prefix site origin gh-pages`
- **Pages from a folder:** point the Pages source at `/site`
- **Any static host:** copy the contents of `site/` to the web root

## Updating content

- The **version** appears in the header, the release boxes and the footer of every
  page. When the toolkit version changes, update it everywhere (search for the old
  version string across `site/`).
- The **changelog** and the field notes are hand-maintained from the release commits.
  Keep them newest-first and dated.
- The **search index** is the `SEARCH_INDEX` array at the top of `js/search.js`; add
  an entry for any new page.
- **Command reference pages** must match the binaries' real flags. Extract them with
  `<binary> -h` rather than writing them from memory.

## Icons

The logo and favicon PNGs in `img/` are generated (star-topology LAN glyph on a navy
tile). The generator is not part of the site itself; regenerate the full size set with
any vector/bitmap tool if the mark changes, keeping `logo.png` (48 px),
`favicon.ico` (16/32 px) and `apple-touch-icon.png` (180 px).

## Design notes

The visual system is a technical field manual: warm paper stock, black ink, hairline
rules, one oxide-red signal colour, a serif reading face and a monospace face for
labels, tables and commands. Layouts are information-dense but fluid — a three-column
manual grid on wide screens, two columns on tablets, and a single column on phones.
Terminal excerpts are dark, flat blocks. There are no gradients, shadows, rounded
corners, stock photography or marketing-language sections.

At 1050 px the manual's right rail drops away and the homepage hero stacks. At 780 px
the primary navigation collapses behind a small `menu` toggle and all grids become a
single column. Print styles hide the site chrome and keep the manual readable on paper.
