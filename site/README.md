# Agent Control Plane site

Static site for ACP. `src/` holds the hand-written pages, styles and script; `content.py` holds every
title, description, excerpt and source record; `build.py` writes `dist/`. Nothing here is deployed: the
gateway's Vercel project excludes `site/`, and the site has no host yet.

```sh
python3 site/build.py                                  # full build, about 4 minutes (renders 24 social images)
python3 site/build.py --fast                           # reuse the last social images
SITE_URL=https://acp.example.org/ python3 site/build.py  # set the real address
python3 -m http.server 8790 -d site/dist &             # then: site/tools/axe.sh, the WCAG 2.0 A/AA audit
```

Requires Python 3.11+, Pillow, Pandoc 3, rsvg-convert and Google Chrome.

The documents are not copied into this repository. The build reads each one, with its dates, from its
own repository: the gateway's from this checkout, the rest from sibling checkouts under `~/Projects`
(or `PROJECTS_DIR`), and the bootstrap documents at their pinned tag. Several come from private
repositories, so a built `dist/` contains text that is not public until the site is.

## What the build produces

| Output | Purpose |
|---|---|
| `index.html`, `install.html`, `coverage.html` | Rendered once in headless Chrome so their content is in the HTML without script |
| `docs.html`, `docs/<id>.html` | The library and one page per document, with contents sidebar, source, license, dates |
| `docs/<id>.md` | Each document as plain text, linked as `rel="alternate"` |
| `credits.html`, `404.html` | Attribution and licenses; a not-found page (noindex) |
| `social/*.png` | 1200×630 share images, one per page and document |
| `favicon.ico`, `favicon.svg`, `apple-touch-icon.png`, `icon-*.png`, `safari-pinned-tab.svg`, `mstile-150x150.png` | Icons |
| `site.webmanifest`, `browserconfig.xml` | App and tile metadata |
| `sitemap.xml`, `robots.txt`, `feed.xml` | Crawling and subscription |
| `llms.txt`, `llms-full.txt`, `humans.txt` | Summaries for language models and people |
| `build/artifact-index.html` | `index.html` without its document wrapper, for the claude.ai artifact host |

Every page carries a description, canonical link, Open Graph and Twitter card tags, theme colors and
schema.org JSON-LD (WebSite, Person, WebPage, BreadcrumbList, plus SoftwareApplication, HowTo,
CollectionPage, TechArticle or ScholarlyArticle as fits). The build warns on unknown icons,
broken links or anchors, skipped heading levels, missing alt text, duplicate titles and descriptions
outside 70–160 characters.

Nothing in the build submits anything to a search engine or other service. IndexNow, Search Console
and similar submissions are left for when the site has its own domain.
