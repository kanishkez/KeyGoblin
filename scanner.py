#!/usr/bin/env python3
import re
import time
import json
import logging
from urllib.parse import urlparse, urljoin, parse_qs
from collections import deque

from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

# Optional AST parsing via tree_sitter. If not installed, scanner falls back to regex
try:
    from tree_sitter import Language, Parser
    TREE_SITTER_AVAILABLE = True
except Exception:
    TREE_SITTER_AVAILABLE = False

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


STATIC_ASSET_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".webp", ".svg", ".gif", ".avif", ".ico",
    ".ttf", ".otf", ".woff", ".woff2",
    ".pbf", ".mvt", ".glb", ".gltf", ".tile",
    ".pdf", ".zip", ".csv", ".xlsx", ".wasm",
    ".css", ".map", ".scss", ".less",
    ".mp4", ".mp3", ".ogg"
)

CDN_HEADER_BLACKLIST = {
    "x-amz-cf-id", "x-amz-cf-pop", "x-amz-meta-", "x-vercel-cache",
    "server", "via", "etag", "age", "x-cache", "cf-ray", "cf-cache-status",
    "x-served-by", "x-timer", "x-request-id", "strict-transport-security",
    "referrer-policy", "report-to", "nel", "cdn-loop", "content-length",
    "content-type", "cache-control", "date"
}

SUSPICIOUS_HEADER_NAME_RE = re.compile(
    r"(authorization|api[-_]?key|x-api[-_]?key|x-amz-|access[-_]?token|bearer)", re.I
)

CONTEXT_KEYWORDS = (
    "token", "auth", "bearer", "secret", "api", "apikey", "api_key",
    "access_token", "client_secret", "firebase", "mapbox", "openai",
    "hf_", "sk-", "eyJ"
)

STRICT_PATTERNS = {
    "hf_token": re.compile(r"\bhf_[A-Za-z0-9]{16,}\b"),
    "google_api": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "mapbox_pk": re.compile(r"\bpk\.[A-Za-z0-9\-_\.]{20,}\b"),
    "openai_sk": re.compile(r"\bsk-[A-Za-z0-9]{16,}\b"),
    "firebase_apikey": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    "generic_kv": re.compile(
        r"(?i)(?:api[_-]?key|apikey|access[_-]?token|client[_-]?secret|secret)"
        r"['\"=:\s]+([A-Za-z0-9\-_\.]{16,})"
    ),
    "bearer_header": re.compile(r"(?i)\bBearer\s+([A-Za-z0-9\-._~+/]+=*)\b"),
}

API_PATH_INDICATORS = (
    "/api/", "/rest/", "/v1/", "/v2/", "/v3/", "/v4/", "/v5/",
    "/graphql", "/inference", "/predict", "/models/", "/embed",
    "/geocode", "/maps/api/", "/auth/", "/oauth/", "/token/",
    "/session", "/login", "/signup", "/users", "/user", "/search",
    "/translate", "/complete", "/generate"
)

COMMON_API_DOMAINS = (
    "api.mapbox.com", "maps.googleapis.com", "api.opencagedata.com",
    "api-inference.huggingface.co", "www.googleapis.com", "youtube.googleapis.com",
    "graph.facebook.com", "api.twitter.com", "discord.com", "slack.com",
    "api.stripe.com", "api.openai.com", "api.github.com", "login.auth0.com",
    "identitytoolkit.googleapis.com", "fcm.googleapis.com",
)

GLOBAL_NAMES_TO_SCAN = (
    "window", "globalThis", "__NEXT_DATA__", "__APP_CONFIG__", "server",
    "CONFIG", "ENV", "process", "window.server", "window.__ENV__",
    "window.__APP_CONFIG__", "window.__RUNTIME_CONFIG__"
)


def _is_static_asset(url: str) -> bool:
    if not url:
        return False
    url = url.split("?", 1)[0].lower()
    return any(url.endswith(ext) for ext in STATIC_ASSET_EXTENSIONS)


def _normalize_api_root(url: str) -> str:
    try:
        p = urlparse(url)
        return f"{p.scheme or 'https'}://{p.netloc}"
    except Exception:
        return url


def _looks_like_api_path(url: str) -> bool:
    if not url:
        return False
    p = urlparse(url)
    path = p.path or ""
    for indict in API_PATH_INDICATORS:
        if indict.lower() in path.lower():
            return True
    q = p.query.lower()
    if "access_token=" in q or "api_key=" in q or "apikey=" in q:
        return True
    if p.netloc.lower() in COMMON_API_DOMAINS:
        return True
    return False


def _is_minified_noise(v: str) -> bool:
    if not v:
        return True
    vv = v.strip().strip('"\'')

    if len(vv) < 16:
        return True
    if re.fullmatch(r"[A-Za-z]{1,20}", vv):
        return True
    if re.fullmatch(r"[A-Za-z0-9]{10,20}", vv):
        return True
    return False


class ASTExtractor:
    """
    If tree_sitter is available, parse JS into AST and extract string literals,
    object properties, and calls that look like config initializers.
    Falls back to simple heuristic extraction if not available.
    """

    def __init__(self):
        self.enabled = TREE_SITTER_AVAILABLE
        if self.enabled:
            try:
                # Build or load a combined library if the user provided one.
                # Attempt to load a prebuilt language bundle at ./build/my-languages.so
                # If not present, fall back to disabled mode.
                SO_PATH = "./build/my-languages.so"
                Language.build_library = getattr(Language, "build_library", None) or None
                self.JS_LANGUAGE = Language(SO_PATH, "javascript")
                self.parser = Parser()
                self.parser.set_language(self.JS_LANGUAGE)
            except Exception:
                self.enabled = False

    def extract_literals(self, js_text: str):
        if not js_text:
            return []
        if not self.enabled:
            return self._fallback_extract(js_text)
        # tree-sitter approach: walk string/identifier nodes
        literals = set()
        try:
            tree = self.parser.parse(bytes(js_text, "utf8"))
            cursor = tree.walk()

            def node_text(node):
                return js_text[node.start_byte:node.end_byte]

            stack = [tree.root_node]
            while stack:
                n = stack.pop()
                if n.type in ("string", "string_fragment"):
                    txt = node_text(n)
                    # strip quotes
                    txt = re.sub(r'^[`"\']|[`"\']$', "", txt)
                    literals.add(txt)
                elif n.type in ("property_identifier", "shorthand_property_identifier"):
                    literals.add(node_text(n))
                elif n.type == "pair":
                    # pair: property: value - take property name literal
                    try:
                        key_node = n.child_by_field_name("key")
                        if key_node is not None:
                            literals.add(node_text(key_node).strip('"\'')) 
                    except Exception:
                        pass
                for c in reversed(n.children):
                    stack.append(c)
        except Exception:
            return self._fallback_extract(js_text)
        return list(literals)

    def _fallback_extract(self, js_text: str):
        candidates = set()
        # common config call patterns: initializeApp({ apiKey: "..." })
        for m in re.finditer(r"apiKey\s*[:=]\s*['\"]([A-Za-z0-9_\-\.]{16,})['\"]", js_text, re.I):
            candidates.add(m.group(1))
        for name in ("AIza", "pk.", "hf_", "sk-", "Bearer", "token", "apikey"):
            for m in re.finditer(r"([A-Za-z0-9_\-\.]{10,80})", js_text):
                v = m.group(1)
                if name in v or v.startswith("pk.") or v.startswith("hf_") or v.startswith("AIza") or v.startswith("sk-"):
                    candidates.add(v)
        return list(candidates)


class APISecurityScannerV4:
    def __init__(self, timeout=60000, headless=True, scan_js=True, crawl_depth=1, same_origin_only=True):
        self.timeout = timeout
        self.headless = headless
        self.scan_js = scan_js
        self.crawl_depth = int(crawl_depth)
        self.same_origin_only = same_origin_only

        self.exposed_keys = {}      # value -> {pattern, sources:set()}
        self.api_endpoints = {}     # root -> set(paths)
        self.suspicious_headers = {} # header -> set(urls)
        self._request_count = 0
        self._ast = ASTExtractor()

    def _record_key(self, value, pattern, source):
        if not value:
            return
        v = value.strip()
        ent = self.exposed_keys.get(v)
        if not ent:
            self.exposed_keys[v] = {"pattern": pattern, "sources": set([source])}
        else:
            ent["sources"].add(source)

    def _record_endpoint(self, url):
        root = _normalize_api_root(url)
        ent = self.api_endpoints.get(root)
        p = urlparse(url)
        path = p.path or "/"
        sample = path + ("?" + p.query if p.query else "")
        if not ent:
            self.api_endpoints[root] = set([sample])
        else:
            ent.add(sample)

    def _record_header(self, header_name, url):
        key = header_name.lower()
        ent = self.suspicious_headers.get(key)
        if not ent:
            self.suspicious_headers[key] = set([url])
        else:
            ent.add(url)

    def _scan_text_patterns(self, text, source):
        if not text:
            return
        for name, pat in STRICT_PATTERNS.items():
            for m in pat.finditer(text):
                val = m.group(0)
                if name != "jwt" and _is_minified_noise(val):
                    window = text[max(0, m.start()-80):m.end()+80].lower()
                    if not any(k in window for k in CONTEXT_KEYWORDS):
                        continue
                self._record_key(val, name, source)

        # generic kv capture group (group 1)
        gpat = STRICT_PATTERNS.get("generic_kv")
        if gpat:
            for m in gpat.finditer(text):
                val = m.group(1)
                if val and not _is_minified_noise(val):
                    self._record_key(val, "generic_kv", source)

    def _scan_js_with_ast(self, js_text, source):
        # AST extraction (string literals / property names) then pattern scan
        literals = self._ast.extract_literals(js_text)
        for lit in literals:
            self._scan_text_patterns(lit, source)
        # Also scan full JS text for endpoints embedded as URLs
        for m in re.finditer(r"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+", js_text):
            u = m.group(0)
            if not _is_static_asset(u) and _looks_like_api_path(u):
                self._record_endpoint(u)

    def _dump_window_globals(self, page, target_url):
        # Evaluate a safe, bounded dump of selected globals and recursively stringify
        script = """
        () => {
            const out = {};
            const keys = Object.keys(window);
            const interesting = ['__NEXT_DATA__','__APP_CONFIG__','__RUNTIME_CONFIG__','server','config','env','__ENV__','process'];
            function safeStringify(o, depth=0) {
                if (depth>5) return "[DEPTH]";
                try {
                    if (o === null) return null;
                    if (typeof o === 'string') return o;
                    if (typeof o === 'number' || typeof o === 'boolean') return o;
                    if (Array.isArray(o)) return o.map(x=>safeStringify(x, depth+1)).slice(0,20);
                    if (typeof o === 'object') {
                        const r = {};
                        for (const k of Object.keys(o).slice(0,50)) {
                            try { r[k] = safeStringify(o[k], depth+1); } catch(e){ r[k] = '[ERROR]'; }
                        }
                        return r;
                    }
                    return String(o);
                } catch(e) { return '[ERROR]'; }
            }
            for (const k of interesting) {
                if (Object.prototype.hasOwnProperty.call(window, k)) {
                    try { out[k] = safeStringify(window[k], 0); } catch(e) { out[k] = '[ERROR]'; }
                }
            }
            // Also a best-effort sample of keys that look like config names
            for (const k of keys) {
                const lk = k.toLowerCase();
                if (lk.includes('config') || lk.includes('env') || lk.includes('server') || lk.includes('runtime')) {
                    try { out[k] = safeStringify(window[k], 0); } catch(e) { out[k] = '[ERROR]'; }
                }
            }
            return out;
        }
        """
        try:
            data = page.evaluate(script)
            # Walk the returned object and scan strings
            def walk(obj, prefix):
                if isinstance(obj, dict):
                    for kk, vv in obj.items():
                        walk(vv, f"{prefix}.{kk}" if prefix else kk)
                elif isinstance(obj, list):
                    for i, item in enumerate(obj[:50]):
                        walk(item, f"{prefix}[{i}]")
                else:
                    if isinstance(obj, str):
                        self._scan_text_patterns(obj, f"window:{prefix}")
            walk(data, "")
            return data
        except Exception:
            return {}

    def _install_runtime_hooks(self, page):
        # Hook fetch, XHR, WebSocket and sendBeacon to capture runtime data
        hook = r"""
        (() => {
            if (window.__SEC_SCAN_HOOKED__) return;
            window.__SEC_SCAN_HOOKED__ = true;
            function trySendMarker(kind, payload) {
                try {
                    window.__SEC_SCAN_EVIDENCE__ = window.__SEC_SCAN_EVIDENCE__ || [];
                    window.__SEC_SCAN_EVIDENCE__.push({kind: kind, payload: payload, ts: Date.now()});
                    if (window.__SEC_SCAN_EVIDENCE__.length>200) window.__SEC_SCAN_EVIDENCE__.shift();
                } catch(e){}
            }
            const origFetch = window.fetch;
            window.fetch = function(...args) {
                trySendMarker('fetch', JSON.stringify(args).slice(0,2000));
                return origFetch.apply(this, args);
            };
            try {
                const XHR = window.XMLHttpRequest;
                const origOpen = XHR.prototype.open;
                const origSend = XHR.prototype.send;
                XHR.prototype.open = function() {
                    trySendMarker('xhr.open', JSON.stringify([arguments[0], arguments[1]]).slice(0,1000));
                    return origOpen.apply(this, arguments);
                };
                XHR.prototype.send = function(body) {
                    trySendMarker('xhr.send', (typeof body === 'string' ? body.slice(0,2000) : '[binary]'));
                    return origSend.apply(this, arguments);
                };
            } catch(e){}
            try {
                const OrigWS = window.WebSocket;
                window.WebSocket = function(url, protocols) {
                    trySendMarker('ws.open', String(url).slice(0,500));
                    return new OrigWS(url, protocols);
                };
            } catch(e){}
            try {
                const origBeacon = navigator.sendBeacon;
                navigator.sendBeacon = function(url, data){
                    trySendMarker('beacon', String(url).slice(0,500));
                    return origBeacon.apply(this, arguments);
                };
            } catch(e){}
        })();
        """
        try:
            page.add_init_script(hook)
        except Exception:
            try:
                page.evaluate(hook)
            except Exception:
                pass

    def _collect_runtime_evidence(self, page):
        try:
            ev = page.evaluate("() => (window.__SEC_SCAN_EVIDENCE__ || [])")
            if isinstance(ev, list):
                for item in ev:
                    payload = item.get("payload", "")
                    if isinstance(payload, str):
                        self._scan_text_patterns(payload, "runtime")
            return ev
        except Exception:
            return []

    def _download_and_scan_script(self, ctx_request, src, base_target):
        try:
            if src.startswith("//"):
                parsed = urlparse(base_target)
                src = f"{parsed.scheme}:{src}"
            elif src.startswith("/"):
                parsed = urlparse(base_target)
                src = f"{parsed.scheme}://{parsed.netloc}{src}"
            else:
                src = urljoin(base_target, src)
        except Exception:
            pass
        if _is_static_asset(src):
            return
        try:
            r = ctx_request.get(src, timeout=self.timeout)
            if not r or not r.ok:
                return
            text = r.text()
            if not text:
                return
            # scan for secrets with AST first
            try:
                self._scan_js_with_ast(text, src)
            except Exception:
                self._scan_text_patterns(text, src)
            # scan for sourcemap references
            for m in re.finditer(r"//# sourceMappingURL=([^\s'\"/]+\.map)|sourceMappingURL=([^\s'\"/]+\.map)", text, re.I):
                sm = (m.group(1) or m.group(2) or "").strip()
                if sm:
                    smurl = urljoin(src, sm)
                    try:
                        smr = ctx_request.get(smurl, timeout=self.timeout)
                        if smr and smr.ok:
                            smtext = smr.text()
                            if smtext:
                                self._scan_text_patterns(smtext, smurl)
                    except Exception:
                        pass
        except Exception:
            pass

    def _collect_page_resources(self, page, ctx_request, target):
        # gather inline scripts + external scripts + resource performance entries
        scripts = []
        try:
            scripts = page.evaluate(
                """() => Array.from(document.scripts).map(s => ({ src: s.src || null, inline: s.textContent || null }))"""
            )
        except Exception:
            scripts = []
        for s in scripts:
            if s.get("inline"):
                js = s.get("inline")
                try:
                    self._scan_js_with_ast(js, target + " (inline)")
                except Exception:
                    self._scan_text_patterns(js, target + " (inline)")
        if self.scan_js:
            for s in scripts:
                src = s.get("src")
                if not src:
                    continue
                self._download_and_scan_script(ctx_request, src, target)
        # performance resources
        try:
            perf = page.evaluate("() => performance.getEntriesByType('resource').map(e=>e.name)")
            if isinstance(perf, list):
                for u in perf:
                    if not u:
                        continue
                    if _is_static_asset(u):
                        continue
                    if _looks_like_api_path(u):
                        self._record_endpoint(u)
        except Exception:
            pass

    def _crawl_links(self, page, base_target, max_pages=20):
        # breadth-first crawl within same origin up to crawl_depth
        parsed_base = urlparse(base_target)
        origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
        visited = set()
        q = deque()
        q.append((base_target, 0))
        pages = []
        while q and len(visited) < max_pages:
            url, depth = q.popleft()
            if url in visited:
                continue
            visited.add(url)
            try:
                page.goto(url, timeout=min(self.timeout, 15000))
            except Exception:
                continue
            pages.append(url)
            if depth < self.crawl_depth:
                try:
                    anchors = page.evaluate("() => Array.from(document.querySelectorAll('a')).map(a => a.href).filter(Boolean)")
                except Exception:
                    anchors = []
                for a in anchors:
                    try:
                        if not a:
                            continue
                        pa = urlparse(a)
                        if self.same_origin_only and pa.netloc and pa.netloc != parsed_base.netloc:
                            continue
                        if a not in visited:
                            q.append((a, depth+1))
                    except Exception:
                        pass
        return pages

    def run(self, target):
        start = time.time()
        logger.info("Starting scan: %s", target)
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=self.headless)
            ctx = browser.new_context()
            page = ctx.new_page()
            page.on("request", lambda r: self._handle_network_request(r))
            page.on("response", lambda r: self._handle_network_response(r))

            try:
                self._install_runtime_hooks(page)
                page.goto(target, timeout=self.timeout)
            except Exception:
                pass

            # Optionally crawl internal links (homepage + subpages)
            pages_scanned = [target]
            try:
                pages_scanned = self._crawl_links(page, target, max_pages=30)
            except Exception:
                pages_scanned = [target]

            for p_url in pages_scanned:
                try:
                    page.goto(p_url, timeout=self.timeout)
                except Exception:
                    pass
                try:
                    self._collect_page_resources(page, ctx.request, p_url)
                except Exception:
                    pass
                try:
                    gw = self._dump_window_globals(page, p_url)
                    # gw scanned inside
                except Exception:
                    pass
                try:
                    self._collect_runtime_evidence(page)
                except Exception:
                    pass

            try:
                ctx.close()
                browser.close()
            except Exception:
                pass

        # Build findings simplified format
        findings = {
            "secrets": [],
            "js_secrets": [],
            "api_endpoints": [],
            "suspicious_headers": [],
            "meta": {
                "total_requests_seen": self._request_count,
                "scan_duration_seconds": round(time.time() - start, 2)
            }
        }

        for v, m in self.exposed_keys.items():
            findings["secrets"].append({"value": v, "pattern": m["pattern"], "sources": list(m["sources"])})

        # js_secrets are merged into secrets in this design; we keep an empty list for compatibility
        for root, paths in self.api_endpoints.items():
            findings["api_endpoints"].append({"root": root, "examples": list(paths)[:5]})

        for hn, urls in self.suspicious_headers.items():
            findings["suspicious_headers"].append({"header_name": hn, "examples": list(urls)[:5]})

        logger.info("Scan finished (requests: %d) in %.2fs", self._request_count, time.time() - start)
        return findings

    # network handlers collect additional runtime data
    def _handle_network_request(self, req):
        try:
            self._request_count += 1
            url = req.url
            headers = dict(req.headers or {})
            if _looks_like_api_path(url):
                if not _is_static_asset(url):
                    self._record_endpoint(url)
            # scan headers
            for hn, hv in headers.items():
                if SUSPICIOUS_HEADER_NAME_RE.search(hn):
                    self._record_header(hn, url)
                if hv:
                    self._scan_text_patterns(hv, url)
            # query params
            try:
                p = urlparse(url)
                qs = parse_qs(p.query)
                for k, vals in qs.items():
                    lk = k.lower()
                    if "access_token" in lk or "api_key" in lk or "apikey" in lk or "token" in lk:
                        for v in vals:
                            self._record_key(v, "query_param", url)
            except Exception:
                pass
            # body (if available)
            try:
                body = req.post_data
                if body:
                    text = body if isinstance(body, str) else str(body)
                    self._scan_text_patterns(text, url)
            except Exception:
                pass
        except Exception:
            pass

    def _handle_network_response(self, res):
        try:
            url = res.url
            headers = dict(res.headers or {})
            for hn, hv in headers.items():
                if hn.lower() in CDN_HEADER_BLACKLIST:
                    continue
                if SUSPICIOUS_HEADER_NAME_RE.search(hn):
                    self._record_header(hn, url)
                if hv:
                    self._scan_text_patterns(hv, url)
            # attempt to read body if content-type is textual
            ct = headers.get("content-type", "")
            if ct and any(x in ct for x in ("application/json", "text/", "javascript", "application/javascript")):
                try:
                    b = res.body()
                    if b:
                        text = b.decode("utf-8", errors="replace") if isinstance(b, (bytes, bytearray)) else str(b)
                        self._scan_text_patterns(text, url)
                except Exception:
                    pass
        except Exception:
            pass


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("target")
    p.add_argument("--timeout", type=int, default=60000)
    p.add_argument("--no-js", action="store_true")
    p.add_argument("--headful", action="store_true")
    p.add_argument("--depth", type=int, default=1, help="crawl depth for internal links")
    args = p.parse_args()

    s = APISecurityScannerV4(timeout=args.timeout, headless=not args.headful, scan_js=not args.no_js, crawl_depth=args.depth)
    out = s.run(args.target)
    print(json.dumps(out, indent=2))
