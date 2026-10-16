# GNULTE website

Static website for the GNULTE toolkit. No build step, no framework, no third-party
scripts — plain semantic HTML, one stylesheet, one small search script.

## Layout

```
site/
  index.html            homepage
  tools.html            tool directory
  docs.html             documentation index
  downloads.html        source downloads and install
  changelog.html        release history
  about.html            project, philosophy, safety, license, contact
  search.html           client-side documentation search
  feed.xml              Atom news feed
  docs/                 manual: install, configuration, usage, troubleshooting, faq
    gnulte.html         command reference, one page per binary
    gnulte-lan.html
    gnulte-scan.html
    gnulte-devices.html
    gnulte-wifi.html
    gnulte-doctor.html
    gnulte-trace.html
    gnulte-top.html
  css/gnulte.css        the stylesheet
  js/search.js          search index + filtering (no dependencies)
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
- The **changelog** and the homepage news list are hand-maintained from the release
  commits. Keep them newest-first and dated.
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

The visual language is deliberately the one a Linux networking project used around
2010: a fixed 960 px centred layout, a dark header band with a compact wordmark,
a horizontal navigation bar, an information-dense three-column body (documentation
navigation, content, sidebar), 1 px borders, alternating table rows, underlined links,
system fonts, and small status/version details. Below 984 px the columns stack into a
single readable column instead of overflowing.
