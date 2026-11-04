#!/usr/bin/env python3
"""Build the ACP site into dist/.

  python3 build.py                     # placeholder address from content.py
  SITE_URL=https://acp.example.org/ python3 build.py

Every document becomes its own static page. Pages the browser builds with script
(the Overview and Coverage) are rendered once in headless Chrome so their content
is in the HTML. Then come the metadata, icons, social images and the small files.
Nothing here contacts a search engine or submits anything.
"""
import datetime as dt
import html
import json
import math
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from xml.sax.saxutils import escape as xesc

import content as C

ROOT = Path(__file__).resolve().parent
SRC, OUT, WORK = ROOT / "src", ROOT / "dist", ROOT / "build"
SITE_URL = os.environ.get("SITE_URL", C.SITE["url"]).rstrip("/") + "/"
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
# A profile of its own, so the build never touches a running Chrome.
CHROME_FLAGS = ["--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check", f"--user-data-dir={ROOT / '.chrome-profile'}"]
FONTS = "https://fonts.googleapis.com/css2?family=Schibsted+Grotesk:wght@500;600;700;800&family=Newsreader:ital,opsz,wght@0,6..72,400;0,6..72,500;1,6..72,400&family=JetBrains+Mono:wght@400;600&display=swap"
e = lambda s: html.escape(str(s), quote=True)
DOCS = {d["id"]: d for d in C.DOCS}
PAGES = {p["file"]: p for p in C.PAGES}
WARN = []
FAST = "--fast" in sys.argv  # reuse the social images from the last full build


def warn(msg):
    WARN.append(msg)


def url(path=""):
    # The home page's canonical address is the site root.
    if path.startswith("index.html"):
        path = path[len("index.html"):]
    return SITE_URL + path


def human_date(iso):
    d = dt.date.fromisoformat(iso)
    return f"{d.day} {d.strftime('%B %Y')}"


# ---------------------------------------------------------------- icons

GLYPHS = dict(re.findall(r"^\s+(\w+): '(.*)',?$", (SRC / "site.js").read_text(), re.M))


def icon(name, size=20):
    return (f'<svg class="ico" width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
            f'stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{GLYPHS[name]}</svg>')


def paint(page):
    """Draw every data-i placeholder into the HTML, so icons need no script."""
    def sub(m):
        tag, attrs, name = m.group(1), m.group(2), m.group(3)
        if name not in GLYPHS:
            warn(f"unknown icon {name}")
            return m.group(0)
        size = re.search(r'data-size="(\d+)"', attrs)
        inner = GLYPHS[name] if tag == "g" else icon(name, int(size.group(1)) if size else 20)
        return f"<{tag}{attrs} data-painted=\"1\">{inner}</{tag}>"
    return re.sub(r'<(span|g)((?:(?!data-painted)[^>])*?data-i="(\w+)"[^>]*)></\1>', sub, page)


# ---------------------------------------------------------------- shared chrome

NAV = [p for p in C.PAGES if p["file"] != "credits.html"]
CURRENT = ' aria-current="page"'


def header(active, pre=""):
    links = "".join(
        f'<a href="{pre}{p["file"]}"{CURRENT if p["file"] == active else ""}>'
        f'<span data-i="{p["icon"]}" data-size="16"></span>{p["nav"]}</a>' for p in NAV)
    return (f'<a class="skip" href="#main">Skip to content</a>\n'
            f'<header class="site"><div class="wrap">\n'
            f'  <a class="brand" href="{pre}index.html"><span class="mark"><span data-i="ShieldCheck" data-size="18"></span></span>Agent Control Plane</a>\n'
            f'  <nav class="nav" aria-label="Site">{links}'
            f'<a class="ext" href="{C.SITE["repo"]}" target="_blank" rel="noopener">GitHub</a></nav>\n'
            f'</div></header>')


def footer(pre=""):
    groups = "".join(
        f'<div><h2>{e(g)}</h2><ul>' + "".join(
            f'<li><a href="{pre}docs/{d["id"]}.html">{e(d["title"])}</a></li>' for d in C.DOCS if d["group"] == g) + "</ul></div>"
        for g, _, _ in C.GROUPS)
    pages = "".join(f'<li><a href="{pre}{p["file"]}">{e(p["nav"])}</a></li>' for p in C.PAGES)
    return f'''<footer class="site-foot">
  <div class="wrap">
    <nav class="foot-map" aria-label="Site map">
      <div><h2>Site</h2><ul>{pages}</ul></div>
      {groups}
      <div><h2>Machine-readable</h2><ul>
        <li><a href="{pre}sitemap.xml" type="application/xml">Sitemap</a></li>
        <li><a href="{pre}feed.xml" type="application/atom+xml">Documents feed (Atom)</a></li>
        <li><a href="{pre}llms.txt" type="text/plain">llms.txt</a></li>
        <li><a href="{pre}llms-full.txt" type="text/plain">llms-full.txt</a></li>
        <li><a href="{pre}humans.txt" type="text/plain">humans.txt</a></li>
      </ul></div>
    </nav>
    <p class="colophon">Compiled {C.SITE["compiled"]} from acp-gateway (main, 7f5cae0), formal-project-bootstrap v0.7.3, agent-control-plane 0.1.0, the protocols register and Chroma Systems Research. <i>The Last Undo</i> material comes from the public introduction and field card at judgmentmachines.com. Each document keeps its source’s license; see <a href="{pre}credits.html">Credits and Sources</a>.</p>
  </div>
</footer>'''


def person():
    return {"@type": "Person", "@id": url("#author"), "name": C.AUTHOR["name"], "url": C.AUTHOR["url"],
            "sameAs": [C.AUTHOR["github"], C.AUTHOR["orcid"]]}


def website():
    return {"@type": "WebSite", "@id": url("#website"), "url": url(), "name": C.SITE["name"], "alternateName": C.SITE["short_name"],
            "description": C.SITE["description"], "inLanguage": C.SITE["lang"], "publisher": {"@id": url("#author")}}


def crumbs_ld(trail):
    return {"@type": "BreadcrumbList", "@id": url(trail[-1][1] + "#breadcrumb"),
            "itemListElement": [{"@type": "ListItem", "position": i + 1, "name": n, "item": url(p)} for i, (n, p) in enumerate(trail)]}


def crumbs_html(trail, pre=""):
    items = []
    for i, (name, path) in enumerate(trail):
        last = i == len(trail) - 1
        href = pre + (path or "index.html")
        items.append(f'<li aria-current="page">{e(name)}</li>' if last else f'<li><a href="{href}">{e(name)}</a></li>')
    return f'<nav class="crumbs" aria-label="Breadcrumb"><ol>{"".join(items)}</ol></nav>'


def head(*, title, description, og_title=None, path, image, image_alt, graph, pre="", og_type="website", article=None,
         keywords=None, alternates=(), rel_links=(), robots="index, follow, max-image-preview:large, max-snippet:-1"):
    if not 70 <= len(description) <= 160:
        warn(f"{path}: description is {len(description)} characters")
    lines = [
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">',
        f"<title>{e(title)}</title>",
        '<meta name="claude:viewport-fit-sides" content="cover">',
        f'<meta name="description" content="{e(description)}">',
        f'<link rel="canonical" href="{url(path)}">',
        f'<meta name="robots" content="{robots}">',
        f'<meta name="author" content="{e(C.AUTHOR["name"])}">',
    ]
    if keywords:
        lines.append(f'<meta name="keywords" content="{e(", ".join(keywords))}">')
    lines += [
        '<meta name="color-scheme" content="light dark">',
        f'<meta name="theme-color" media="(prefers-color-scheme: light)" content="{C.SITE["theme_light"]}">',
        f'<meta name="theme-color" media="(prefers-color-scheme: dark)" content="{C.SITE["theme_dark"]}">',
        f'<meta name="application-name" content="{C.SITE["short_name"]}">',
        f'<meta name="apple-mobile-web-app-title" content="{C.SITE["short_name"]}">',
        '<meta name="format-detection" content="telephone=no">',
        '<meta name="referrer" content="strict-origin-when-cross-origin">',
        '<meta name="msapplication-TileColor" content="#111c17">',
        f'<meta name="msapplication-config" content="{pre}browserconfig.xml">',
        f'<link rel="icon" href="{pre}favicon.ico" sizes="32x32">',
        f'<link rel="icon" href="{pre}favicon.svg" type="image/svg+xml">',
        f'<link rel="apple-touch-icon" href="{pre}apple-touch-icon.png">',
        f'<link rel="mask-icon" href="{pre}safari-pinned-tab.svg" color="#111c17">',
        f'<link rel="manifest" href="{pre}site.webmanifest">',
        f'<link rel="alternate" type="application/atom+xml" title="ACP documents" href="{pre}feed.xml">',
        f'<link rel="sitemap" type="application/xml" href="{pre}sitemap.xml">',
        f'<link rel="author" type="text/plain" href="{pre}humans.txt">',
    ]
    for rel, href, extra in rel_links:
        lines.append(f'<link rel="{rel}" href="{href}"{extra}>')
    for typ, href, ttl in alternates:
        lines.append(f'<link rel="alternate" type="{typ}" href="{href}" title="{e(ttl)}">')
    lines += [
        f'<meta property="og:site_name" content="{e(C.SITE["name"])}">',
        f'<meta property="og:type" content="{og_type}">',
        f'<meta property="og:title" content="{e(og_title or title)}">',
        f'<meta property="og:description" content="{e(description)}">',
        f'<meta property="og:url" content="{url(path)}">',
        f'<meta property="og:locale" content="{C.SITE["locale"]}">',
        f'<meta property="og:image" content="{url(image)}">',
        '<meta property="og:image:type" content="image/png">',
        '<meta property="og:image:width" content="1200">',
        '<meta property="og:image:height" content="630">',
        f'<meta property="og:image:alt" content="{e(image_alt)}">',
    ]
    if article:
        lines += [f'<meta property="article:published_time" content="{article["published"]}">',
                  f'<meta property="article:modified_time" content="{article["modified"]}">',
                  f'<meta property="article:author" content="{C.AUTHOR["url"]}">',
                  f'<meta property="article:section" content="{e(article["section"])}">']
        lines += [f'<meta property="article:tag" content="{e(k)}">' for k in keywords or []]
    lines += [
        '<meta name="twitter:card" content="summary_large_image">',
        f'<meta name="twitter:title" content="{e(og_title or title)}">',
        f'<meta name="twitter:description" content="{e(description)}">',
        f'<meta name="twitter:image" content="{url(image)}">',
        f'<meta name="twitter:image:alt" content="{e(image_alt)}">',
        '<link rel="preconnect" href="https://fonts.googleapis.com">',
        '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>',
        f'<link rel="stylesheet" href="{FONTS}">',
        f'<link rel="stylesheet" href="{pre}site.css">',
        '<script>document.documentElement.classList.add("js");document.documentElement.lang=document.documentElement.lang||"en"</script>',
        '<script type="application/ld+json">' + json.dumps({"@context": "https://schema.org", "@graph": graph}, ensure_ascii=False).replace("</", "<\\/") + "</script>",
    ]
    return "\n".join(lines)


def webpage(path, name, description, image, trail, typ="WebPage", **extra):
    node = {"@type": typ, "@id": url(path + "#webpage"), "url": url(path), "name": name, "description": description,
            "inLanguage": C.SITE["lang"], "isPartOf": {"@id": url("#website")},
            "primaryImageOfPage": {"@type": "ImageObject", "url": url(image), "width": 1200, "height": 630},
            "breadcrumb": {"@id": url(trail[-1][1] + "#breadcrumb")}, "dateModified": C.SITE["compiled"]}
    node.update(extra)
    return node


# ---------------------------------------------------------------- documents

def git_dates(d):
    repo = C.REPOS[d["repo"]]
    out = subprocess.run(["git", "-C", str(repo["dir"]), "log", "--format=%cs", *([repo["ref"]] if repo.get("ref") else []), "--", d["path"]],
                         capture_output=True, text=True).stdout.split()
    if not out:
        warn(f"{d['id']}: no git history for {d['path']}")
        return C.SITE["compiled"], C.SITE["compiled"]
    return d.get("published", out[-1]), out[0]


def fence_ruled(text):
    """Documents converted from Word keep ruled text tables; keep them preformatted."""
    out, open_ = [], False
    for line in text.split("\n"):
        if re.match(r"^\s{0,3}-{20,}\s*$", line):
            open_ = not open_
            out.append("```text\n" + line if open_ else line + "\n```")
        else:
            out.append(line)
    return "\n".join(out)


def prep(d, raw):
    if d.get("code"):
        return f"{d['intro']}\n\n```{d['code']}\n{raw.rstrip()}\n```\n"
    text = re.sub(r"\A---\n.*?\n---\n", "", raw, flags=re.S)
    if d.get("strip_until"):
        text = text[text.index(d["strip_until"]):]
    lines = text.lstrip("\n").split("\n")
    if lines and lines[0].startswith("# "):
        lines = lines[1:]
    text = fence_ruled("\n".join(lines))
    # \cite{a, b} in the paper becomes a Pandoc citation, resolved against its bibliography.
    return re.sub(r"\\cite\{([^}]*)\}", lambda m: "[" + "; ".join("@" + k.strip() for k in m.group(1).split(",")) + "]", text)


def pandoc(d, text):
    shift = "1" if re.search(r"^# ", text, re.M) else "0"
    if d.get("bibliography"):
        args = ["-f", "markdown+gfm_auto_identifiers", "--citeproc", "--bibliography", str(C.REPOS[d["repo"]]["dir"] / d["bibliography"]), "--mathml"]
    else:
        args = ["-f", "gfm"]
    res = subprocess.run(["pandoc", *args, "-t", "html5", "--wrap=none", "--highlight-style=pygments", f"--shift-heading-level-by={shift}"],
                         input=text, capture_output=True, text=True)
    if res.returncode:
        sys.exit(f"pandoc failed on {d['id']}: {res.stderr}")
    if res.stderr.strip():
        warn(f"{d['id']}: pandoc: {res.stderr.strip()[:200]}")
    return res.stdout


def rewrite_links(d, frag):
    repo = C.REPOS[d["repo"]]
    base_dir = str(Path(d["path"]).parent)

    def sub(m):
        attrs_before, href, attrs_after, body = m.group(1), m.group(2), m.group(3), m.group(4)
        if re.match(r"^(https?:|mailto:|#)", href):
            return m.group(0)
        path, _, anchor = href.partition("#")
        name = path.split("/")[-1]
        if name in C.LINKS:
            return f'<a{attrs_before}href="{C.LINKS[name]}.html{"#" + anchor if anchor else ""}"{attrs_after}>{body}</a>'
        if repo["web"]:
            target = os.path.normpath(os.path.join(base_dir, path)).lstrip("./")
            return f'<a{attrs_before}href="{repo["web"]}{target}{"#" + anchor if anchor else ""}"{attrs_after}>{body}</a>'
        return f'<span class="unlinked" title="Not published with this site">{body}</span>'
    return re.sub(r'<a([^>]*?)href="([^"]*)"([^>]*)>(.*?)</a>', sub, frag, flags=re.S)


def polish(frag):
    frag = re.sub(r'<a href="#cb\d+-\d+" aria-hidden="true" tabindex="-1"></a>', "", frag)
    frag = frag.replace('<img src="../github-app/logo.png" alt="ACP Agent Control Plane" width="96" align="right">',
                        '<img class="doc-figure" src="../assets/github-app-logo.png" alt="The ACP Agent Control Plane GitHub App icon" width="96" height="96" loading="lazy" decoding="async">')
    # Each table scrolls in its own focusable region, named after the section it sits in.
    parts, section, seen = re.split(r"(<h[2-4] id=\"[^\"]+\"[^>]*>.*?</h[2-4]>|<table>)", frag, flags=re.S), "Document", {}
    for k, part in enumerate(parts):
        if part.startswith("<h"):
            section = re.sub(r"<[^>]+>", "", part).strip()
        elif part == "<table>":
            seen[section] = seen.get(section, 0) + 1
            label = f"Table: {section}" + (f" ({seen[section]})" if seen[section] > 1 else "")
            parts[k] = f'<div class="twrap" role="region" aria-label="{e(label)}" tabindex="0"><table>'
    frag = "".join(parts).replace("</table>", "</table></div>")
    # A header row left blank in the source carries no headers; an empty header cell becomes a plain cell.
    frag = re.sub(r"<thead>\s*<tr[^>]*>(?:\s*<th[^>]*>\s*</th>)+\s*</tr>\s*</thead>", "", frag)
    frag = re.sub(r"<th([^>]*)>\s*</th>", r"<td\1></td>", frag)
    frag = re.sub(r"<pre([ >])", r'<pre tabindex="0"\1', frag)
    # Wide equations scroll inside their own focusable box.
    eq = iter(range(1, 1000))
    frag = re.sub(r'(<math display="block".*?</math>)', lambda m: f'<span class="math-wrap" role="region" aria-label="Equation {next(eq)}, scrolls sideways" tabindex="0">{m.group(1)}</span>', frag, flags=re.S)
    # A long formula inside a sentence can't wrap, so it scrolls in place too.
    frag = re.sub(r'<math display="inline".*?</math>', lambda m: m.group(0) if len(m.group(0)) < 800 else
                  f'<span class="math-wrap inline" role="region" aria-label="Formula, scrolls sideways" tabindex="0">{m.group(0)}</span>', frag, flags=re.S)
    # A link to each section, for sharing a place in a long document.
    frag = re.sub(r'<(h[2-4]) id="([^"]+)"([^>]*)>(.*?)</\1>',
                  lambda m: f'<{m.group(1)} id="{m.group(2)}"{m.group(3)}>{m.group(4)}<a class="anchor" href="#{m.group(2)}" aria-label="Link to this section">#</a></{m.group(1)}>',
                  frag, flags=re.S)
    return frag


def toc_of(frag):
    heads = re.findall(r'<h2 id="([^"]+)"[^>]*>(.*?)</h2>', frag, re.S)
    level = "h2"
    if len(heads) < 3:
        heads = re.findall(r'<h[23] id="([^"]+)"[^>]*>(.*?)</h[23]>', frag, re.S)
    clean = lambda s: re.sub(r"<[^>]+>", "", re.sub(r'<a class="anchor".*?</a>', "", s)).strip()
    return [(i, clean(t)) for i, t in heads if clean(t) and clean(t) != "References"] + \
        ([("refs", "References")] if 'id="refs"' in frag else [])


def source(d, path=None):
    """The document's text, read from its repository: at the pinned tag when there is one, else as checked out."""
    repo = C.REPOS[d["repo"]]
    path = path or d["path"]
    if repo.get("ref"):
        return subprocess.run(["git", "-C", str(repo["dir"]), "show", f'{repo["ref"]}:{path}'],
                              capture_output=True, text=True, check=True).stdout
    return (repo["dir"] / path).read_text()


def build_doc(d, i):
    raw = source(d)
    text = prep(d, raw)
    frag = polish(rewrite_links(d, pandoc(d, text)))
    toc = toc_of(frag)
    words = len(re.findall(r"\w+", re.sub(r"<[^>]+>", " ", frag)))
    minutes = max(1, math.ceil(words / 230))
    published, modified = git_dates(d)
    d.update(published=published, modified=modified, words=words, minutes=minutes)
    path = f"docs/{d['id']}.html"
    img = f"social/doc-{d['id']}.png"
    alt = f"{d['title']}, from the {d['group']} documents of Agent Control Plane"
    d["image"], d["image_alt"] = img, alt
    repo = C.REPOS[d["repo"]]
    lic_name, lic_url = C.LICENSES[repo["license"]]
    src_url = (repo["web"] + d["path"]) if repo["web"] else None
    md_name = d.get("file", d["id"] + ".md")
    trail = [("Overview", "index.html"), ("Docs", "docs.html"), (d["title"], path)]
    prev_d, next_d = (C.DOCS[i - 1] if i else None), (C.DOCS[i + 1] if i + 1 < len(C.DOCS) else None)

    art = {"@type": d.get("type", "TechArticle"), "@id": url(path + "#article"), "headline": d.get("full_title", d["title"])[:110],
           "name": d["title"], "description": d["description"], "abstract": d["excerpt"],
           "author": {"@id": url("#author")}, "publisher": {"@id": url("#author")},
           "datePublished": published, "dateModified": modified, "inLanguage": "en",
           "image": {"@type": "ImageObject", "url": url(img), "width": 1200, "height": 630, "caption": alt},
           "mainEntityOfPage": {"@id": url(path + "#webpage")}, "isPartOf": {"@id": url("docs.html#collection")},
           "articleSection": d["group"], "keywords": d["keywords"], "wordCount": words, "timeRequired": f"PT{minutes}M",
           "encoding": {"@type": "MediaObject", "contentUrl": url("docs/" + md_name),
                        "encodingFormat": "text/yaml" if d.get("code") else "text/markdown"}}
    if d.get("status"):
        art["version"] = d["status"]
    if lic_url:
        art["license"] = lic_url
    if src_url:
        art["isBasedOn"] = src_url
    if d.get("affiliation"):
        art["author"] = {"@type": "Person", "@id": url("#author"), "name": C.AUTHOR["name"], "sameAs": [C.AUTHOR["orcid"], C.AUTHOR["github"]],
                         "affiliation": {"@type": "Organization", "name": d["affiliation"]}}
    graph = [website(), person(), webpage(path, d["title"], d["description"], img, trail), crumbs_ld(trail), art]

    rel = []
    if lic_url:
        rel.append(("license", lic_url, ""))
    if prev_d:
        rel.append(("prev", f'{prev_d["id"]}.html', ""))
    if next_d:
        rel.append(("next", f'{next_d["id"]}.html', ""))
    hd = head(title=f'{d["title"]} · ACP Docs', og_title=d["title"], description=d["description"], path=path, image=img, image_alt=alt, graph=graph, pre="../",
              og_type="article", keywords=d["keywords"],
              article={"published": published, "modified": modified, "section": d["group"]},
              alternates=[("text/yaml" if d.get("code") else "text/markdown", md_name, f'{d["title"]} as plain text')], rel_links=rel)

    toc_items = "".join(f'<li><a href="#{a}">{e(t)}</a></li>' for a, t in toc)
    toc_html = (f'<nav class="toc-side" aria-label="On this page"><h2>On this page</h2><ol>{toc_items}</ol></nav>'
                f'<details class="toc-inline"><summary>On this page</summary><ol>{toc_items}</ol></details>') if len(toc) >= 2 else ""
    src_html = f'<a href="{src_url}" target="_blank" rel="noopener">{e(repo["label"])}</a>' if src_url else e(repo["label"])
    lic_html = f'<a href="{lic_url}" target="_blank" rel="noopener license">{e(lic_name)}</a>' if lic_url else e(lic_name)
    byline = ""
    if d.get("affiliation"):
        byline = (f'<p class="byline">By <a rel="author noopener" href="{C.AUTHOR["orcid"]}" target="_blank">{e(C.AUTHOR["name"])}</a>, '
                  f'{e(d["affiliation"])} · <span class="full-title">{e(d["full_title"])}</span></p>')
    pager = []
    if prev_d:
        pager.append(f'<a class="prev" rel="prev" href="{prev_d["id"]}.html"><span>Previous</span>{e(prev_d["title"])}</a>')
    if next_d:
        pager.append(f'<a class="next" rel="next" href="{next_d["id"]}.html"><span>Next</span>{e(next_d["title"])}</a>')
    status = f' · {e(d["status"])}' if d.get("status") else ""
    page = f'''<!doctype html>
<html lang="en">
<head>
{hd}
</head>
<body class="docpage">
{header("docs.html", "../")}
<main id="main" class="wrap">
  {crumbs_html(trail, "../")}
  <article class="doc" aria-labelledby="doc-title">
    <header class="doc-head">
      <div class="eyebrow"><a href="../docs.html#{slug(d["group"])}">{e(d["group"])}</a>{status}</div>
      <h1 id="doc-title">{e(d["title"])}</h1>
      <p class="dek">{e(d["excerpt"])}</p>
      {byline}
      <dl class="doc-meta">
        <div><dt>Updated</dt><dd><time datetime="{modified}">{human_date(modified)}</time></dd></div>
        <div><dt>Reading time</dt><dd>{minutes} min</dd></div>
        <div><dt>Source</dt><dd>{src_html}</dd></div>
        <div><dt>License</dt><dd>{lic_html}</dd></div>
        <div><dt>Plain text</dt><dd><a href="{md_name}" type="{"text/yaml" if d.get("code") else "text/markdown"}">{md_name}</a></dd></div>
      </dl>
    </header>
    <div class="doc-body{" has-toc" if toc_html else ""}">
      {toc_html}
      <div class="md prose">
{frag}
      </div>
    </div>
    <footer class="doc-foot">
      <nav class="pager" aria-label="Previous and next document">{"".join(pager)}</nav>
      <p><a href="../docs.html">All documents</a> · <a href="#doc-title">Back to top</a></p>
    </footer>
  </article>
</main>
{footer("../")}
<script src="../site.js" defer></script>
</body>
</html>
'''
    (WORK / "docs").mkdir(parents=True, exist_ok=True)
    (WORK / path).write_text(page)
    (WORK / "docs" / md_name).write_text(source(d))


def slug(s):
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")


# ---------------------------------------------------------------- site pages

def page_graph(p, trail):
    path, img = p["file"], p["image"]
    if p["kind"] == "home":
        node = webpage(path, p["title"], p["description"], img, trail, about={"@id": url("#software")})
        software = {"@type": "SoftwareApplication", "@id": url("#software"), "name": C.SITE["name"], "alternateName": "ACP",
                    "description": C.SITE["description"], "applicationCategory": "DeveloperApplication",
                    "applicationSubCategory": "Authorization service for AI agents", "operatingSystem": "macOS, Linux",
                    "softwareVersion": "0.7.3", "softwareRequirements": "Python 3.11 or later, Git", "url": url(),
                    "image": url(img), "author": {"@id": url("#author")}, "isAccessibleForFree": True,
                    "installUrl": url("install.html"), "softwareHelp": {"@id": url("docs.html#webpage")},
                    "sameAs": [C.SITE["repo"], "https://github.com/zachshallbetter/formal-project-bootstrap"]}
        code = [{"@type": "SoftwareSourceCode", "name": "acp-gateway", "codeRepository": C.SITE["repo"], "programmingLanguage": "Python",
                 "targetProduct": {"@id": url("#software")}, "author": {"@id": url("#author")}},
                {"@type": "SoftwareSourceCode", "name": "formal-project-bootstrap", "codeRepository": "https://github.com/zachshallbetter/formal-project-bootstrap",
                 "programmingLanguage": "Python", "license": C.LICENSES["MIT"][1], "version": "0.7.3", "targetProduct": {"@id": url("#software")}, "author": {"@id": url("#author")}}]
        return [website(), person(), node, crumbs_ld(trail), software, *code]
    if p["kind"] == "howto":
        steps = [("step-get", "Get the bootstrap", "Clone formal-project-bootstrap and check out the v0.7.3 tag."),
                 ("step-install", "Install it into your project", "Run init-project.py for a new or existing project, or bootstrap upgrade --commit for one on an older bootstrap."),
                 ("step-connect", "Connect this machine", "Configure the production endpoint set, store the gateway token with acp login, then run acp init in the project."),
                 ("step-policy", "Put the repository under a policy", "The repository’s owner registers it once with policy-admin.py register OWNER/NAME --apply."),
                 ("step-check", "Check everything", "Run acp status. Every line should read OK, and each problem comes with its fix.")]
        howto = {"@type": "HowTo", "@id": url(path + "#howto"), "name": "Install ACP in a project", "description": p["description"],
                 "image": url(img), "inLanguage": "en",
                 "tool": [{"@type": "HowToTool", "name": "Python 3.11 or later"}, {"@type": "HowToTool", "name": "Git"}],
                 "supply": [{"@type": "HowToSupply", "name": "A gateway token"}, {"@type": "HowToSupply", "name": "A GitHub repository"}],
                 "step": [{"@type": "HowToStep", "position": i + 1, "name": n, "text": t, "url": url(f"{path}#{a}")} for i, (a, n, t) in enumerate(steps)]}
        return [website(), person(), webpage(path, p["title"], p["description"], img, trail, mainEntity={"@id": url(path + "#howto")}), crumbs_ld(trail), howto]
    if p["kind"] == "collection":
        coll = webpage(path, p["title"], p["description"], img, trail, typ="CollectionPage")
        coll["@id"] = url(path + "#collection")
        coll["mainEntity"] = {"@type": "ItemList", "numberOfItems": len(C.DOCS), "itemListElement": [
            {"@type": "ListItem", "position": i + 1, "url": url(f"docs/{d['id']}.html"), "name": d["title"]} for i, d in enumerate(C.DOCS)]}
        return [website(), person(), coll, crumbs_ld(trail)]
    if p["kind"] == "about":
        return [website(), person(), webpage(path, p["title"], p["description"], img, trail, typ="AboutPage"), crumbs_ld(trail)]
    art = {"@type": "TechArticle", "@id": url(path + "#article"), "headline": "What ACP does, and what covers it", "description": p["description"],
           "author": {"@id": url("#author")}, "publisher": {"@id": url("#author")}, "datePublished": "2026-11-02", "dateModified": C.SITE["compiled"],
           "image": url(img), "mainEntityOfPage": {"@id": url(path + "#webpage")}, "about": {"@id": url("#software")}, "inLanguage": "en"}
    return [website(), person(), webpage(path, p["title"], p["description"], img, trail), crumbs_ld(trail), art]


def trail_for(p):
    return [("Overview", "index.html")] if p["file"] == "index.html" else [("Overview", "index.html"), (p["nav"] if p["file"] != "credits.html" else p["title"], p["file"])]


def site_head(p):
    trail = trail_for(p)
    return head(title=p["title"], description=p["description"], path=p["file"], image=p["image"], image_alt=p["image_alt"],
                graph=page_graph(p, trail), og_type="website")


def wrap_page(p, body, body_class=""):
    trail = trail_for(p)
    crumbs = crumbs_html(trail) if len(trail) > 1 else ""
    return f'''<!doctype html>
<html lang="en">
<head>
{site_head(p)}
</head>
<body{f' class="{body_class}"' if body_class else ""}>
{header(p["file"])}
<main id="main">
<div class="wrap">{crumbs}</div>
{body}
</main>
{footer()}
<script src="site.js" defer></script>
</body>
</html>
'''


def assemble_source_page(name):
    """index, install and coverage are written by hand in src/; give them the shared head, header and footer."""
    p = PAGES[name]
    s = (SRC / name).read_text()
    s = s.replace("<!--HEAD-->", site_head(p))
    s = s.replace("<!--HEADER-->", header(name))
    trail = trail_for(p)
    s = s.replace("<!--CRUMBS-->", f'<div class="wrap">{crumbs_html(trail)}</div>' if len(trail) > 1 else "")
    s = s.replace("<!--FOOTER-->", footer())
    if "<!--" in s.replace("<!--[", ""):
        leftover = re.findall(r"<!--[A-Z]+-->", s)
        if leftover:
            warn(f"{name}: unreplaced markers {leftover}")
    (WORK / name).write_text(s)


def docs_index():
    p = PAGES["docs.html"]
    groups = []
    for g, ic, blurb in C.GROUPS:
        cards = "".join(f'''
      <li class="doc-card">
        <h3><a href="docs/{d["id"]}.html">{e(d["title"])}</a></h3>
        <p>{e(d["description"])}</p>
        <dl>
          {f'<div><dt>Status</dt><dd>{e(d["status"])}</dd></div>' if d.get("status") else ""}
          <div><dt>Updated</dt><dd><time datetime="{d["modified"]}">{human_date(d["modified"])}</time></dd></div>
          <div><dt>Length</dt><dd>{d["minutes"]} min read</dd></div>
        </dl>
      </li>''' for d in C.DOCS if d["group"] == g)
        n = sum(1 for d in C.DOCS if d["group"] == g)
        groups.append(f'''
  <section class="lib-sec" id="{slug(g)}" aria-labelledby="h-{slug(g)}">
    <div class="wrap">
      <div class="lib-head"><span data-i="{ic}" data-size="26"></span><div><h2 id="h-{slug(g)}">{e(g)}</h2><p>{e(blurb)} {n} document{"s" if n > 1 else ""}.</p></div></div>
      <ul class="doc-cards">{cards}
      </ul>
    </div>
  </section>''')
    jump = "".join(f'<li><a href="#{slug(g)}">{e(g)}</a></li>' for g, _, _ in C.GROUPS)
    body = f'''<div class="wrap">
  <div class="page-head">
    <div class="eyebrow">Docs</div>
    <h1>Read the sources</h1>
    <p>Every document this site draws on, each on its own page with its source, license and last update. Each is also available as plain Markdown, and all of them together in <a href="llms-full.txt">llms-full.txt</a>.</p>
    <nav aria-label="Document groups"><ul class="jump">{jump}</ul></nav>
  </div>
</div>{"".join(groups)}'''
    (WORK / "docs.html").write_text(wrap_page(p, body))


FONT_CREDITS = [
    ("Schibsted Grotesk", "Bakken & Bæck for Schibsted", "Headings and interface", "https://fonts.google.com/specimen/Schibsted+Grotesk"),
    ("Newsreader", "Production Type", "Body text", "https://fonts.google.com/specimen/Newsreader"),
    ("JetBrains Mono", "JetBrains", "Code, labels and data", "https://fonts.google.com/specimen/JetBrains+Mono"),
]


def license_link(name, href):
    return f'<a href="{href}" target="_blank" rel="noopener license">{e(name)}</a>' if href else e(name)


def credits():
    p = PAGES["credits.html"]
    rows = "".join(
        f'<tr><td><a href="docs/{d["id"]}.html">{e(d["title"])}</a></td><td>{e(C.REPOS[d["repo"]]["label"])}<br><code>{e(d["path"])}</code></td>'
        f'<td>{license_link(*C.LICENSES[C.REPOS[d["repo"]]["license"]])}</td></tr>'
        for d in C.DOCS)
    fonts = "".join(f'<tr><td><a href="{u}" target="_blank" rel="noopener">{e(n)}</a></td><td>{e(by)}</td><td>{e(use)}</td><td><a href="https://openfontlicense.org" target="_blank" rel="noopener license">SIL Open Font License 1.1</a></td></tr>' for n, by, use, u in FONT_CREDITS)
    body = f'''<div class="wrap">
  <div class="page-head">
    <div class="eyebrow">Credits</div>
    <h1>Credits and sources</h1>
    <p>{e(p["excerpt"])}</p>
  </div>
</div>
<section class="tight" aria-labelledby="h-made">
  <div class="wrap prose-block">
    <h2 id="h-made">Who made it</h2>
    <p>ACP, formal-project-bootstrap, the protocols and this site are the work of <a href="{C.AUTHOR["url"]}" target="_blank" rel="noopener author">{e(C.AUTHOR["name"])}</a> (<a href="{C.AUTHOR["github"]}" target="_blank" rel="noopener">GitHub</a>, <a href="{C.AUTHOR["orcid"]}" target="_blank" rel="noopener">ORCID</a>). Corrections are welcome as issues on <a href="{C.SITE["repo"]}/issues" target="_blank" rel="noopener">acp-gateway</a>.</p>
  </div>
</section>
<section aria-labelledby="h-docs">
  <div class="wrap">
    <div class="head"><h2 id="h-docs">Documents and their licenses</h2><p>Each document is reproduced as it stood on {human_date(C.SITE["compiled"])}. Its license is the one its source repository declares. Where a repository declares none, no license is granted beyond reading it here.</p></div>
    <div class="twrap" role="region" aria-label="Documents and licenses, scrolls sideways" tabindex="0"><table>
      <caption class="sr-only">Every document on this site with its source and license</caption>
      <thead><tr><th scope="col">Document</th><th scope="col">Source</th><th scope="col">License</th></tr></thead>
      <tbody>{rows}</tbody>
    </table></div>
  </div>
</section>
<section aria-labelledby="h-ideas">
  <div class="wrap prose-block">
    <h2 id="h-ideas">Work this site draws on</h2>
    <p><i>The Last Undo</i> is a book from Judgment Machines. The Overview quotes its idea of the last undo and adapts its field card; both come only from the public <a href="https://judgmentmachines.com/books/the-last-undo/read" target="_blank" rel="noopener">introduction</a> and the <a href="https://judgmentmachines.com/assets/last-undo-field-card-v1.0.0.pdf" target="_blank" rel="noopener">field card (PDF)</a>. The ACP readings beside the card’s questions are this site’s own.</p>
    <p><a href="docs/commitment-assurance.html"><i>Distance from Gray</i></a> is reproduced under the Creative Commons Attribution 4.0 license, with its references resolved from the paper’s own bibliography.</p>
  </div>
</section>
<section aria-labelledby="h-type">
  <div class="wrap">
    <div class="head"><h2 id="h-type">Typefaces</h2><p>Served by Google Fonts. Each falls back to a system face if it can’t load.</p></div>
    <div class="twrap" role="region" aria-label="Typefaces, scrolls sideways" tabindex="0"><table>
      <caption class="sr-only">Typefaces used on this site</caption>
      <thead><tr><th scope="col">Typeface</th><th scope="col">Designed by</th><th scope="col">Used for</th><th scope="col">License</th></tr></thead>
      <tbody>{fonts}</tbody>
    </table></div>
  </div>
</section>
<section aria-labelledby="h-built">
  <div class="wrap prose-block">
    <h2 id="h-built">Icons and tools</h2>
    <p>The icons were drawn for this site: line work in the text color with one lit lamp, after the aspects of a railway signal. They carry no outside license. Documents are converted with <a href="https://pandoc.org" target="_blank" rel="noopener">Pandoc</a>, and the site is assembled by a short Python script that also renders the social images in headless Chrome.</p>
    <p>No analytics, cookies or trackers run on this site. Fonts load from Google Fonts.</p>
  </div>
</section>'''
    (WORK / "credits.html").write_text(wrap_page(p, body))


def not_found():
    p = {"file": "404.html", "title": "Page not found", "nav": "Not found", "image": "social/page-index.png",
         "image_alt": PAGES["index.html"]["image_alt"], "description": "That page isn’t here. Start from the Overview, the install guide, the coverage map or the document library.", "kind": "about"}
    trail = [("Overview", "index.html"), ("Page not found", "404.html")]
    hd = head(title=p["title"], description=p["description"], path="404.html", image=p["image"], image_alt=p["image_alt"],
              graph=[website(), person()], robots="noindex, follow")
    links = "".join(f'<li><a href="{q["file"]}">{e(q["nav"])}</a> · {e(q["description"])}</li>' for q in C.PAGES)
    page = f'''<!doctype html>
<html lang="en">
<head>
{hd}
</head>
<body>
{header("")}
<main id="main">
<div class="wrap">
  <div class="page-head">
    <div class="eyebrow">404</div>
    <h1>That page isn’t here</h1>
    <p>The address may be mistyped, or the page may have moved when each document got its own page. One of these will get you back on track.</p>
  </div>
  <ul class="lost">{links}</ul>
</div>
</main>
{footer()}
<script src="site.js" defer></script>
</body>
</html>
'''
    (WORK / "404.html").write_text(page)


# ---------------------------------------------------------------- prerender

def prerender(name):
    """Run the page's own script once, in headless Chrome, and keep the result."""
    res = subprocess.run([CHROME, *CHROME_FLAGS, "--allow-file-access-from-files", "--virtual-time-budget=4000", "--dump-dom",
                          (WORK / name).as_uri() + "?prerender"], capture_output=True, text=True, timeout=90)
    dom = res.stdout
    if "<body" not in dom:
        sys.exit(f"prerender failed for {name}: {res.stderr[:400]}")
    dom = re.sub(r'<html([^>]*?) class="js"', r"<html\1", dom, count=1)
    dom = dom.replace('<div class="toast" id="toast" hidden=""></div>', "")
    (WORK / name).write_text("<!doctype html>\n" + dom)


# ---------------------------------------------------------------- finishing passes

def finish(page):
    page = paint(page)
    # Say that a link opens a new tab, for people who can't see the arrow.
    page = re.sub(r'(<a\b[^>]*target="_blank"[^>]*>)(.*?)(</a>)',
                  lambda m: m.group(0) if "sr-only" in m.group(2) else f'{m.group(1)}{m.group(2)}<span class="sr-only"> (opens in a new tab)</span>{m.group(3)}',
                  page, flags=re.S)
    return page


# ---------------------------------------------------------------- images

def chrome_shot(html_path, png, w, h, profile="shot"):
    # Chrome often exits non-zero on teardown after writing the file, so check the file instead.
    flags = [f for f in CHROME_FLAGS if not f.startswith("--user-data-dir")] + [f"--user-data-dir={ROOT / '.chrome-profile' / profile}"]
    subprocess.run([CHROME, *flags, "--hide-scrollbars", "--force-device-scale-factor=1",
                    f"--window-size={w},{h}", "--virtual-time-budget=5000", f"--screenshot={png}", html_path.as_uri()],
                   capture_output=True, timeout=90)
    if not Path(png).exists():
        sys.exit(f"screenshot failed for {html_path.name}")


def social_card(slug_, eyebrow, title, line, glyph, path_label):
    size = 76 if len(title) <= 22 else 64 if len(title) <= 34 else 54
    return f'''<!doctype html><html><head><meta charset="utf-8">
<link rel="stylesheet" href="{FONTS}">
<style>
html,body{{margin:0;width:1200px;height:630px;overflow:hidden}}
body{{background:#0b1310;color:#e6ede7;font-family:"Newsreader",Georgia,serif;position:relative}}
.grid{{position:absolute;inset:0;background-image:linear-gradient(#16231c 1px,transparent 1px),linear-gradient(90deg,#16231c 1px,transparent 1px);background-size:48px 48px;opacity:.55}}
.card{{position:absolute;inset:56px 64px;display:grid;grid-template-columns:1fr 250px;gap:40px}}
.brand{{display:flex;align-items:center;gap:14px;font:700 26px "Schibsted Grotesk",Arial,sans-serif;letter-spacing:-.01em}}
.plate{{width:46px;height:46px;border-radius:10px;background:#111c17;border:1.5px solid #2a3d33;display:grid;place-items:center;color:#e6ede7}}
.eyebrow{{margin-top:70px;font:600 19px "JetBrains Mono",monospace;letter-spacing:.12em;text-transform:uppercase;color:#d9ad5f}}
h1{{margin:18px 0 0;font:800 {size}px/1.02 "Schibsted Grotesk",Arial,sans-serif;letter-spacing:-.03em;max-width:15ch}}
p{{margin:24px 0 0;font-size:29px;line-height:1.35;color:#a9b9af;max-width:34ch}}
.foot{{position:absolute;left:0;bottom:0;display:flex;align-items:center;gap:14px;font:400 18px "JetBrains Mono",monospace;color:#8fa397}}
.lamps{{display:flex;gap:8px}}.lamps i{{width:14px;height:14px;border-radius:50%;display:block}}
.big{{align-self:center;justify-self:end;width:250px;height:250px;border-radius:28px;background:#111c17;border:1.5px solid #213229;display:grid;place-items:center;color:#c7d2ca}}
.ico .lamp{{fill:#f0b443;stroke:none}}
</style></head><body><div class="grid"></div>
<div class="card"><div>
<div class="brand"><span class="plate">{icon("ShieldCheck", 28)}</span>Agent Control Plane</div>
<div class="eyebrow">{e(eyebrow)}</div>
<h1>{e(title)}</h1>
<p>{e(line)}</p>
<div class="foot"><span class="lamps"><i style="background:#3fd08a"></i><i style="background:#f39a3c"></i><i style="background:#ff6253"></i></span>{e(path_label)}</div>
</div><div class="big">{icon(glyph, 168)}</div></div></body></html>'''


def social_images():
    (WORK / "og").mkdir(parents=True, exist_ok=True)
    (OUT / "social").mkdir(parents=True, exist_ok=True)
    jobs = []
    group_icon = {g: ic for g, ic, _ in C.GROUPS}
    for p in C.PAGES:
        stem = p["file"].removesuffix(".html")
        p["image"] = f"social/page-{stem}.png"
        lead = {"index": "An authorization service for AI agents", "install": "Set up ACP in a new or existing project",
                "coverage": "Thirteen capabilities and what grounds them", "docs": "Nineteen source documents, each on its own page",
                "credits": "Sources, licenses and typefaces"}[stem]
        jobs.append((f"page-{stem}", "acp" if stem == "index" else stem, p["title"], lead, "ShieldCheck" if stem == "index" else p["icon"], "acp · " + (p["file"] if stem != "index" else "overview")))
    for d in C.DOCS:
        line = d["description"].split(":")[0] if len(d["description"].split(":")[0]) < 90 else d["description"][:88].rsplit(" ", 1)[0] + "…"
        jobs.append((f"doc-{d['id']}", d["group"] + (" · " + d["status"] if d.get("status") else ""), d["title"], line,
                     group_icon[d["group"]], f"acp · docs/{d['id']}"))
    from concurrent.futures import ThreadPoolExecutor
    from PIL import Image

    def one(job):
        k, (name, eyebrow, title, line, glyph, label) = job
        src = WORK / "og" / f"{name}.html"
        src.write_text(social_card(name, eyebrow, title, line, glyph, label))
        png = OUT / "social" / f"{name}.png"
        chrome_shot(src, png, 1200, 630, profile=f"shot-{k % 6}")
        im = Image.open(png).convert("RGB")
        if im.size != (1200, 630):
            warn(f"{name}: screenshot was {im.size}, cropped")
            im = im.crop((0, 0, 1200, 630))
        im.save(png, optimize=True)
    if FAST and all((OUT / "social" / f"{j[0]}.png").exists() for j in jobs):
        return
    with ThreadPoolExecutor(6) as pool:
        # Profiles are shared by job index modulo 6, so give each worker its own slice.
        list(pool.map(lambda k: [one((j, jobs[j])) for j in range(k, len(jobs), 6)], range(6)))


MARK = '<path d="M22 47V19M42 47V19M17.5 47h29M22 26.5h20"/><circle cx="32" cy="36" r="4.6" fill="{lamp}" stroke="none"/>'


def favicons():
    from PIL import Image
    plate = lambda bg, fg, lamp, rx, scale=1.0: (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="{rx}" fill="{bg}"/>'
        f'<g fill="none" stroke="{fg}" stroke-width="4.2" stroke-linecap="round" stroke-linejoin="round" transform="translate(32 33) scale({scale}) translate(-32 -33)">'
        + MARK.format(lamp=lamp) + "</g></svg>")
    (OUT / "favicon.svg").write_text(plate("#111c17", "#e6ede7", "#f0b443", 14, 1.12))
    (OUT / "safari-pinned-tab.svg").write_text(
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><g fill="none" stroke="#000" stroke-width="4.2" stroke-linecap="round" stroke-linejoin="round">'
        + MARK.format(lamp="#000") + "</g></svg>")
    (WORK / "icon-full.svg").write_text(plate("#111c17", "#e6ede7", "#f0b443", 0, 1.0))
    (WORK / "icon-mask.svg").write_text(plate("#111c17", "#e6ede7", "#f0b443", 0, 0.78))
    render = lambda svg, size, out: subprocess.run(["rsvg-convert", "-w", str(size), "-h", str(size), "-o", str(out), str(svg)], check=True)
    for size, name in [(180, "apple-touch-icon.png"), (192, "icon-192.png"), (512, "icon-512.png")]:
        render(WORK / "icon-full.svg", size, OUT / name)
    render(WORK / "icon-mask.svg", 512, OUT / "icon-maskable-512.png")
    render(WORK / "icon-full.svg", 150, OUT / "mstile-150x150.png")
    render(OUT / "favicon.svg", 256, WORK / "favicon-256.png")
    Image.open(WORK / "favicon-256.png").save(OUT / "favicon.ico", sizes=[(16, 16), (32, 32), (48, 48)])


# ---------------------------------------------------------------- small files

def small_files():
    all_pages = [(p["file"], C.SITE["compiled"], p["image"], p["image_alt"]) for p in C.PAGES] + \
                [(f"docs/{d['id']}.html", d["modified"], d["image"], d["image_alt"]) for d in C.DOCS]
    sm = ['<?xml version="1.0" encoding="UTF-8"?>',
          '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:image="http://www.google.com/schemas/sitemap-image/1.1">']
    for path, mod, img, alt in all_pages:
        loc = url("" if path == "index.html" else path)
        sm.append(f"  <url><loc>{xesc(loc)}</loc><lastmod>{mod}</lastmod>"
                  f"<image:image><image:loc>{xesc(url(img))}</image:loc></image:image></url>")
    sm.append("</urlset>")
    (OUT / "sitemap.xml").write_text("\n".join(sm) + "\n")

    (OUT / "robots.txt").write_text(f"""# Agent Control Plane
# Everything here is public documentation.
# A plain-text summary for language models is at {url("llms.txt")}

User-agent: *
Allow: /
Disallow: /404.html

Sitemap: {url("sitemap.xml")}
""")

    (OUT / "humans.txt").write_text(f"""/* TEAM */
Author: {C.AUTHOR["name"]}
Site: {C.AUTHOR["url"]}
GitHub: {C.AUTHOR["github"]}
ORCID: {C.AUTHOR["orcid"]}

/* THANKS */
The Last Undo, Judgment Machines: https://judgmentmachines.com/books/the-last-undo/read
Schibsted Grotesk: Bakken & Bæck for Schibsted
Newsreader: Production Type
JetBrains Mono: JetBrains
Pandoc: https://pandoc.org

/* SITE */
Last update: {C.SITE["compiled"].replace("-", "/")}
Language: English
Doctype: HTML5
Standards: HTML5, CSS, schema.org JSON-LD, Open Graph, Atom 1.0, Sitemaps 0.9, llms.txt
Accessibility: built to WCAG 2.0 AA. Checked with automated tools only; no manual audit yet.
Components: Pandoc, a Python build script, headless Chrome for social images, an original icon set
Privacy: no analytics, cookies or trackers. Fonts load from Google Fonts.
""")

    groups = []
    for g, _, blurb in C.GROUPS:
        items = "\n".join(f"- [{d['title']}]({url('docs/' + d.get('file', d['id'] + '.md'))}): {d['description']}" for d in C.DOCS if d["group"] == g)
        groups.append(f"## {g}\n\n{blurb}\n\n{items}")
    (OUT / "llms.txt").write_text(f"""# {C.SITE["name"]}

> {C.SITE["description"]}

ACP has three parts. acp-gateway is the policy decision service: it holds signed policies, reads GitHub itself as evidence and returns one of eight decisions (A0 ALLOW to A7 VERIFY_RECOVERY). The ACP client ships in every project made with formal-project-bootstrap, at `.agents/acp/`, and fails closed when it can't get a valid decision. agent-control-plane is an earlier, separate admission tool that isn't connected to the gateway.

An ALLOW covers one action, one ref and one commit, and lasts about 60 seconds. Self-reported state never authorizes. Anything ACP can't verify is refused.

Each link below is the document's plain Markdown. The HTML page for each is at the same path with `.html`. Everything together: {url("llms-full.txt")}

{(chr(10) * 2).join(groups)}

## Optional

- [Overview]({url()}): {PAGES["index.html"]["description"]}
- [Install ACP]({url("install.html")}): {PAGES["install.html"]["description"]}
- [ACP Coverage]({url("coverage.html")}): {PAGES["coverage.html"]["description"]}
- [Credits and Sources]({url("credits.html")}): {PAGES["credits.html"]["description"]}
""")

    full = [f"# {C.SITE['name']}: every document\n\n> {C.SITE['description']}\n\nCompiled {C.SITE['compiled']}. {len(C.DOCS)} documents. Each section gives its source, license and canonical page.\n"]
    for d in C.DOCS:
        repo = C.REPOS[d["repo"]]
        raw = source(d).strip()
        if d.get("code"):
            raw = f"```{d['code']}\n{raw}\n```"
        full.append(f"\n\n---\n\n<!-- document: {d['id']} -->\n# {d['title']}\n\n- Page: {url('docs/' + d['id'] + '.html')}\n- Group: {d['group']}\n"
                    f"- Source: {repo['label']} · {d['path']}\n- License: {C.LICENSES[repo['license']][0]}\n- Updated: {d['modified']}\n\n> {d['excerpt']}\n\n{raw}\n")
    (OUT / "llms-full.txt").write_text("".join(full))

    entries = []
    for d in sorted(C.DOCS, key=lambda d: d["modified"], reverse=True):
        link = url(f"docs/{d['id']}.html")
        entries.append(f"""  <entry>
    <title>{xesc(d["title"])}</title>
    <link rel="alternate" type="text/html" href="{xesc(link)}"/>
    <id>{xesc(link)}</id>
    <published>{d["published"]}T00:00:00Z</published>
    <updated>{d["modified"]}T00:00:00Z</updated>
    <category term="{xesc(d["group"])}"/>
    <summary>{xesc(d["description"])}</summary>
    <content type="text">{xesc(d["excerpt"])}</content>
  </entry>""")
    (OUT / "feed.xml").write_text(f"""<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom" xml:lang="en">
  <title>Agent Control Plane: documents</title>
  <subtitle>{xesc(PAGES["docs.html"]["description"])}</subtitle>
  <link rel="self" type="application/atom+xml" href="{xesc(url("feed.xml"))}"/>
  <link rel="alternate" type="text/html" href="{xesc(url("docs.html"))}"/>
  <id>{xesc(url("feed.xml"))}</id>
  <updated>{max(d["modified"] for d in C.DOCS)}T00:00:00Z</updated>
  <author><name>{xesc(C.AUTHOR["name"])}</name><uri>{xesc(C.AUTHOR["url"])}</uri></author>
  <icon>{xesc(url("favicon.svg"))}</icon>
  <logo>{xesc(url("icon-512.png"))}</logo>
{chr(10).join(entries)}
</feed>
""")

    (OUT / "site.webmanifest").write_text(json.dumps({
        "name": C.SITE["name"], "short_name": C.SITE["short_name"], "description": C.SITE["description"], "lang": "en", "dir": "ltr",
        "start_url": "./", "scope": "./", "display": "browser", "background_color": C.SITE["theme_dark"], "theme_color": C.SITE["theme_dark"],
        "categories": ["developer", "productivity", "security"],
        "icons": [{"src": "icon-192.png", "sizes": "192x192", "type": "image/png"}, {"src": "icon-512.png", "sizes": "512x512", "type": "image/png"},
                  {"src": "icon-maskable-512.png", "sizes": "512x512", "type": "image/png", "purpose": "maskable"},
                  {"src": "favicon.svg", "sizes": "any", "type": "image/svg+xml"}]}, indent=2) + "\n")
    (OUT / "browserconfig.xml").write_text("""<?xml version="1.0" encoding="utf-8"?>
<browserconfig><msapplication><tile><square150x150logo src="mstile-150x150.png"/><TileColor>#111c17</TileColor></tile></msapplication></browserconfig>
""")


# ---------------------------------------------------------------- checks

def check():
    """Every internal link and anchor resolves, every page has one h1, headings don't skip, images have alt text."""
    pages = sorted(p for p in OUT.rglob("*.html"))
    ids, titles, descs = {}, {}, {}
    for f in pages:
        s = f.read_text()
        ids[f] = set(re.findall(r'\bid="([^"]+)"', s))
        titles[f] = re.search(r"<title>(.*?)</title>", s).group(1)
        descs[f] = (re.search(r'<meta name="description" content="([^"]*)"', s) or [None, None])[1]
    for f in pages:
        s = f.read_text()
        rel = f.relative_to(OUT)
        if len(re.findall(r"<h1\b", s)) != 1:
            warn(f"{rel}: {len(re.findall(r'<h1', s))} h1 elements")
        levels = [int(x) for x in re.findall(r"<h([1-6])\b", re.sub(r'<footer class="site-foot">.*?</footer>', "", s, flags=re.S))]
        for a, b in zip(levels, levels[1:]):
            if b > a + 1:
                warn(f"{rel}: heading jumps h{a} to h{b}")
                break
        for img in re.findall(r"<img\b[^>]*>", s):
            if 'alt="' not in img:
                warn(f"{rel}: image without alt: {img[:80]}")
        for href in re.findall(r'href="([^"]+)"', s):
            if re.match(r"^(https?:|mailto:|data:)", href):
                continue
            path, _, anchor = href.partition("#")
            target = (f.parent / path).resolve() if path else f
            if path and not target.exists():
                warn(f"{rel}: broken link {href}")
            elif anchor and target.suffix == ".html" and anchor not in ids.get(target, set()):
                warn(f"{rel}: missing anchor {href}")
        if "application/ld+json" in s:
            for blob in re.findall(r'<script type="application/ld\+json">(.*?)</script>', s, re.S):
                json.loads(blob.replace("<\\/", "</"))
    dup = {t for t in titles.values() if list(titles.values()).count(t) > 1}
    if dup:
        warn(f"duplicate titles: {dup}")


# ---------------------------------------------------------------- main

def main():
    keep = ROOT / ".social-keep"
    if FAST and (OUT / "social").exists():
        shutil.rmtree(keep, ignore_errors=True)
        shutil.move(str(OUT / "social"), keep)
    shutil.rmtree(OUT, ignore_errors=True)
    shutil.rmtree(WORK, ignore_errors=True)
    OUT.mkdir()
    if FAST and keep.exists():
        shutil.move(str(keep), OUT / "social")
    WORK.mkdir()
    print("social images")
    social_images()
    print("documents")
    for i, d in enumerate(C.DOCS):
        build_doc(d, i)
    print("pages")
    for name in ("index.html", "install.html", "coverage.html"):
        assemble_source_page(name)
    docs_index()
    credits()
    not_found()
    shutil.copy(SRC / "site.css", WORK / "site.css")
    shutil.copy(SRC / "site.js", WORK / "site.js")
    (WORK / "assets").mkdir(exist_ok=True)
    shutil.copy(C.GATEWAY / "github-app" / "logo.png", WORK / "assets" / "github-app-logo.png")
    print("prerender")
    for name in ("index.html", "install.html", "coverage.html"):
        prerender(name)
    for f in WORK.rglob("*"):
        if f.is_dir() or f.parts[len(WORK.parts)] in ("og",) or f.name.startswith(("icon-", "favicon-")):
            continue
        dest = OUT / f.relative_to(WORK)
        dest.parent.mkdir(parents=True, exist_ok=True)
        if f.suffix == ".html":
            dest.write_text(finish(f.read_text()))
        else:
            shutil.copy(f, dest)
    print("icons and small files")
    favicons()
    small_files()
    artifact_index()
    check()
    n = sum(1 for _ in OUT.rglob("*") if _.is_file())
    print(f"built {n} files into dist/ for {SITE_URL}")
    for w in WARN:
        print("  WARN", w)


def artifact_index():
    """The artifact host wraps index.html in its own document, so publish the head's contents and the body without the wrapper."""
    s = (OUT / "index.html").read_text()
    hd = re.search(r"<head>(.*?)</head>", s, re.S).group(1)
    hd = re.sub(r'<meta charset="utf-8">\s*|<meta name="viewport"[^>]*>\s*', "", hd)
    body = re.search(r"<body[^>]*>(.*)</body>", s, re.S).group(1)
    (WORK / "artifact-index.html").write_text(hd.strip() + "\n" + body.strip() + "\n")


if __name__ == "__main__":
    main()
