// Agent Control Plane: small enhancements. Every page reads in full without this file;
// the build runs it once in headless Chrome (?prerender) so generated content is in the HTML.
const PRERENDER = /prerender/.test(location.search);
const ISSUE = n => `<a href="https://github.com/zachshallbetter/acp-gateway/issues/${n}" target="_blank" rel="noopener">#${n}<span class="sr-only"> (opens in a new tab)</span></a>`;
const $ = s => document.querySelector(s);
const esc = s => String(s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
// A link to a section of a document in the library.
const ref = (doc, anchor, label) => `<a class="ref" href="docs/${doc}.html${anchor ? "#" + anchor : ""}">${esc(label)}</a>`;

// Icons: a small set drawn for ACP. Line work in the text color, one filled "lamp" in the accent,
// the way a signal shows one lit aspect. data-i="Name" on an HTML element or an SVG <g>.
const GLYPHS = {
  Bot: '<rect x="5" y="8" width="14" height="11" rx="3"/><path d="M12 8V5.4M9.5 12.5v2M14.5 12.5v2"/><circle class="lamp" cx="12" cy="3.6" r="1.7"/>',
  Terminal: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M7 10l3 2.5L7 15"/><rect class="lamp" x="12.5" y="13.6" width="4.5" height="1.9" rx=".95"/>',
  ShieldCheck: '<path d="M6 21V4M18 21V4M3.5 21h17M6 8.5h12"/><circle class="lamp" cx="12" cy="14" r="2.4"/>',
  FileSignature: '<path d="M14 3H7a1 1 0 0 0-1 1v16a1 1 0 0 0 1 1h10a1 1 0 0 0 1-1V7z"/><path d="M14 3v4h4M9 10h6M9 13h3.5"/><circle class="lamp" cx="14.5" cy="17" r="2.4"/>',
  ScrollText: '<rect x="5" y="3" width="14" height="18" rx="2"/><path d="M8.5 8h7M8.5 12h7M8.5 16h3.5"/><circle class="lamp" cx="15.5" cy="16" r="1.6"/>',
  ScanSearch: '<circle cx="10.5" cy="10.5" r="6"/><path d="M15 15l5.5 5.5"/><circle class="lamp" cx="10.5" cy="10.5" r="2.1"/>',
  Lock: '<path d="M8 11V8a4 4 0 0 1 8 0v3"/><rect x="5.5" y="11" width="13" height="9.5" rx="2"/><circle class="lamp" cx="12" cy="15.75" r="1.7"/>',
  UserRound: '<circle cx="12" cy="8" r="3.6"/><path d="M5 20.5c.8-3.8 3.6-6 7-6s6.2 2.2 7 6"/><circle class="lamp" cx="18.6" cy="4.8" r="1.6"/>',
  KeyRound: '<circle cx="8" cy="12" r="4"/><path d="M12 12h9M17.5 12v3M20.5 12v2.5"/><circle class="lamp" cx="8" cy="12" r="1.5"/>',
  Fingerprint: '<circle cx="12" cy="12" r="7"/><path d="M12 2.5v4M12 17.5v4M2.5 12h4M17.5 12h4"/><circle class="lamp" cx="12" cy="12" r="2"/>',
  Hourglass: '<circle cx="12" cy="13.5" r="7.5"/><path d="M12 13.5v-4M9.5 2.5h5M12 2.5V6"/><circle class="lamp" cx="12" cy="13.5" r="1.5"/>',
  Undo2: '<path d="M8.5 5L4 9.5 8.5 14"/><path d="M4 9.5h9.5a5.5 5.5 0 0 1 0 11H10"/><circle class="lamp" cx="9" cy="20.5" r="1.5"/>',
  Hand: '<circle cx="12" cy="5.5" r="2.8"/><path d="M12 8.3V15M7.5 11.5h9M9 21l3-6 3 6"/><circle class="lamp" cx="17.2" cy="11.5" r="1.5"/>',
  Coins: '<circle cx="12" cy="12" r="8.2"/><circle cx="12" cy="12" r="4.6"/><circle class="lamp" cx="12" cy="12" r="1.6"/>',
  Waypoints: '<circle cx="5.5" cy="6" r="2.5"/><circle cx="18.5" cy="6" r="2.5"/><path d="M7.2 8l3.6 7.6M16.8 8l-3.6 7.6"/><circle class="lamp" cx="12" cy="18.4" r="2.6"/>',
  ClipboardCheck: '<rect x="5" y="4.5" width="14" height="16.5" rx="2"/><path d="M9.5 4.5V3h5v1.5M8.5 13l2.5 2.5 4.5-5"/><circle class="lamp" cx="12" cy="3.4" r="1.3"/>',
  Map: '<path d="M5 19c4 0 3-7 7-7s3-7 7-7"/><circle cx="5" cy="19" r="2.2"/><circle class="lamp" cx="19" cy="5" r="2.2"/>',
  Download: '<path d="M12 3v11M7.5 9.5L12 14l4.5-4.5M4 16.5V19a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2.5"/>',
  Layers: '<path d="M12 3.5l8.5 4.5L12 12.5 3.5 8z"/><path d="M3.5 12.5L12 17l8.5-4.5M3.5 16.5L12 21l8.5-4.5"/><circle class="lamp" cx="12" cy="8" r="1.5"/>',
  BookOpen: '<path d="M3 5.5c3-1 6-.8 9 1.5v13c-3-2.3-6-2.5-9-1.5zM21 5.5c-3-1-6-.8-9 1.5v13c3-2.3 6-2.5 9-1.5z"/>',
  Check: '<path d="M5 12.5l4.5 4.5L19 7.5"/>',
  Copy: '<rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V5a1 1 0 0 0-1-1H5a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h3"/>',
  Info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6"/><circle class="lamp" cx="12" cy="7.6" r="1.5"/>',
  TriangleAlert: '<path d="M12 3.5L21 20H3z"/><path d="M12 9.5v4.5"/><circle class="lamp" cx="12" cy="16.9" r="1.4"/>',
  Laptop: '<rect x="4.5" y="5" width="15" height="10" rx="1.5"/><path d="M2.5 19h19"/><circle class="lamp" cx="12" cy="10" r="1.7"/>',
  Gavel: '<path d="M9 3.5h6v4a2 2 0 0 1-1 1.7V12h-4V9.2A2 2 0 0 1 9 7.5z"/><path d="M5 12h14v3.5H5zM4 20h16"/><circle class="lamp" cx="12" cy="6" r="1.4"/>',
  ListChecks: '<path d="M4 6.5l1.5 1.5L8 5.5M4 12.5l1.5 1.5L8 11.5M4 18.5l1.5 1.5L8 17.5M11 7h9M11 13h9M11 19h9"/>',
  Rocket: '<path d="M12 19V6.5M7.5 11L12 6.5l4.5 4.5M4.5 3.5h15"/><circle class="lamp" cx="12" cy="20" r="1.6"/>',
  ArrowUpCircle: '<circle cx="12" cy="12" r="9"/><path d="M12 16.5V8M8.5 11.5L12 8l3.5 3.5"/>',
  Trash2: '<path d="M4 7h16M9 7V4.5h6V7M6.5 7l1 13h9l1-13M10 11v5.5M14 11v5.5"/>',
  FolderTree: '<path d="M4.5 4v13.5a2 2 0 0 0 2 2h3.5M4.5 9h5.5"/><rect x="11" y="6" width="9" height="6" rx="1.5"/><rect x="11" y="15.5" width="9" height="6" rx="1.5"/>',
  FileText: '<path d="M14 3H7a1 1 0 0 0-1 1v16a1 1 0 0 0 1 1h10a1 1 0 0 0 1-1V7z"/><path d="M14 3v4h4M9 11h6M9 14.5h6M9 18h3.5"/>',
  BookMarked: '<path d="M5 4h11a2 2 0 0 1 2 2v15H7a2 2 0 0 1-2-2zM5 17.5a2 2 0 0 1 2-2h11"/><path class="lamp" d="M10 4h4v6l-2-1.5L10 10z"/>',
  Eye: '<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z"/><circle cx="12" cy="12" r="3.2"/><circle class="lamp" cx="12" cy="12" r="1.4"/>',
  Siren: '<rect x="3" y="8" width="18" height="6" rx="1"/><path d="M7.5 8l-3 6M12.5 8l-3 6M17.5 8l-3 6M6 14v6.5M18 14v6.5"/><circle class="lamp" cx="12" cy="4.5" r="1.6"/>',
  MessageSquareWarning: '<path d="M4 5h16v11h-9l-4 3.5V16H4z"/><path d="M12 8v3.2"/><circle class="lamp" cx="12" cy="13.5" r="1.2"/>',
  Scale: '<path d="M12 4.5V20M7 20h10M5 7h14M5 7l-2.5 6h5zM19 7l-2.5 6h5z"/><circle class="lamp" cx="12" cy="4" r="1.6"/>',
  Package: '<path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z"/><path d="M4 7.5L12 12l8-4.5M12 12v9"/>',
  Users: '<circle cx="9" cy="8" r="3.2"/><path d="M3 20c.7-3.4 3-5.4 6-5.4s5.3 2 6 5.4"/><circle cx="17" cy="9" r="2.6"/><path d="M16 14.6c2.6.2 4.4 2 5 5.4"/>',
  Github: '<circle cx="6.5" cy="5.5" r="2.2"/><circle cx="6.5" cy="18.5" r="2.2"/><path d="M6.5 7.7v8.6M17.5 10.2c0 4-11 2-11 6"/><circle class="lamp" cx="17.5" cy="8" r="2.2"/>',
  CloudOff: '<path d="M12 21v-9.5M8 21h8"/><rect x="8.5" y="2.5" width="7" height="9" rx="3.5"/><circle class="lamp" cx="12" cy="7" r="1.7"/>'
};
function iconParts(name) { return GLYPHS[name] || ""; }
function icon(name, size = 20) {
  const parts = iconParts(name);
  return parts ? `<svg class="ico" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${parts}</svg>` : "";
}
function paintIcons(root = document) {
  root.querySelectorAll("[data-i]").forEach(el => {
    if (el.dataset.painted) return;
    el.innerHTML = el instanceof SVGElement ? iconParts(el.dataset.i) : icon(el.dataset.i, +(el.dataset.size || 20));
    el.dataset.painted = "1";
  });
}

function toast(msg) {
  let t = $("#toast");
  if (!t) { document.body.insertAdjacentHTML("beforeend", '<div class="toast" id="toast" role="status" hidden></div>'); t = $("#toast"); }
  t.textContent = msg; t.hidden = false;
  clearTimeout(toast.timer); toast.timer = setTimeout(() => { t.hidden = true; }, 2600);
}
function selectText(el) {
  const r = document.createRange(); r.selectNodeContents(el);
  const s = getSelection(); s.removeAllRanges(); s.addRange(r);
  toast("Selected. Press Cmd+C or Ctrl+C to copy.");
}

// Copy buttons on command blocks
document.querySelectorAll("pre.cmd").forEach(p => {
  if (!p.querySelector(".copy")) p.insertAdjacentHTML("beforeend", '<button class="copy" type="button" aria-label="Copy command"><span data-i="Copy" data-size="14"></span>Copy</button>');
});
document.addEventListener("click", e => {
  const btn = e.target.closest(".copy");
  if (!btn) return;
  const code = btn.parentElement.querySelector("code");
  try { navigator.clipboard.writeText(code.textContent).then(() => toast("Copied"), () => selectText(code)); }
  catch (err) { selectText(code); }
});

// Document pages: mark the section being read in the sidebar.
const tocLinks = [...document.querySelectorAll(".toc-side a")];
if (tocLinks.length && "IntersectionObserver" in window) {
  const byId = new Map(tocLinks.map(a => [decodeURIComponent(a.hash.slice(1)), a]));
  const seen = new Set();
  const io = new IntersectionObserver(entries => {
    entries.forEach(en => en.isIntersecting ? seen.add(en.target.id) : seen.delete(en.target.id));
    const current = [...byId.keys()].find(id => seen.has(id));
    if (current) tocLinks.forEach(a => a === byId.get(current) ? a.setAttribute("aria-current", "true") : a.removeAttribute("aria-current"));
  }, { rootMargin: "0px 0px -70% 0px" });
  byId.forEach((_, id) => { const h = document.getElementById(id); if (h) io.observe(h); });
}
// Close the inline contents after a jump on small screens.
document.querySelectorAll(".toc-inline a").forEach(a => a.addEventListener("click", () => a.closest("details").removeAttribute("open")));

paintIcons();
