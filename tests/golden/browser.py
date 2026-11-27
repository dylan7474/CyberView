"""A small headless-Chromium driver for the golden tests (Chrome DevTools Protocol over a websocket).

What the golden tests need from a browser, and nothing more:
  * a frozen clock (Date is fixed before any page script runs), so due dates and "overdue" never move;
  * the outside world replayed from a recording (EPSS, CISA KEV, endoflife.date), or recorded once, so
    the numbers never depend on the network; anything not recorded is refused;
  * run a script in the page and get its JSON result; collect page errors.

Needs: chromium (or google-chrome) and the Python package `websockets` (Debian: python3-websockets).
"""
import asyncio
import base64
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request

# 27 Nov 2026 12:00 UTC: the clock every golden run sees
FROZEN_MS = 1795780800000

CLOCK_JS = """(() => {
  const T = %d, D = Date;
  class FD extends D { constructor(...a) { if (a.length) super(...a); else super(T); } static now() { return T; } }
  FD.UTC = D.UTC; FD.parse = D.parse; window.Date = FD;
})();""" % FROZEN_MS


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def find_chrome():
    for n in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
        p = shutil.which(n)
        if p:
            return p
    raise SystemExit("golden tests need chromium or google-chrome on the PATH")


def is_local(url):
    return url.startswith(("http://127.0.0.1", "https://127.0.0.1", "http://localhost", "https://localhost", "data:", "blob:"))


class Browser:
    """mode 'replay': external requests answered from `net` (url -> {status, type, body}), others refused.
       mode 'record': external requests go out and are written into `net`."""

    def __init__(self, net=None, mode="replay", width=1400, height=1000):
        self.net = net if net is not None else {}
        self.mode = mode
        self.errors = []
        self.refused = set()
        self.local = []          # the page's own requests (the tests check what a page downloads)
        self.width, self.height = width, height

    async def __aenter__(self):
        import websockets
        self.port = free_port()
        self.profile = tempfile.mkdtemp(prefix="cvgolden")
        self.proc = subprocess.Popen([find_chrome(), "--headless=new", "--no-sandbox", "--disable-gpu", "--hide-scrollbars", "--ignore-certificate-errors",
                                      f"--window-size={self.width},{self.height}", f"--remote-debugging-port={self.port}", f"--user-data-dir={self.profile}", "about:blank"],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        tabs = None
        for _ in range(100):
            try:
                tabs = json.load(urllib.request.urlopen(f"http://127.0.0.1:{self.port}/json")); break
            except Exception:
                time.sleep(0.1)
        if tabs is None:
            raise RuntimeError("chromium did not start")
        ws_url = [t for t in tabs if t["type"] == "page"][0]["webSocketDebuggerUrl"]
        self.ws = await websockets.connect(ws_url, max_size=2 ** 30)
        self.n, self.pend = 0, {}
        self.reader = asyncio.create_task(self._read())
        await self.call("Runtime.enable")
        await self.call("Page.enable")
        await self.call("Page.addScriptToEvaluateOnNewDocument", source=CLOCK_JS)
        stage = "Response" if self.mode == "record" else "Request"
        await self.call("Fetch.enable", patterns=[{"urlPattern": "*", "requestStage": stage}])
        return self

    async def __aexit__(self, *a):
        self.reader.cancel()
        try:
            await self.ws.close()
        except Exception:
            pass
        self.proc.terminate()
        try:
            self.proc.wait(5)
        except Exception:
            self.proc.kill()
        shutil.rmtree(self.profile, ignore_errors=True)

    async def call(self, method, **params):
        self.n += 1
        i = self.n
        fut = asyncio.get_event_loop().create_future()
        self.pend[i] = fut
        await self.ws.send(json.dumps({"id": i, "method": method, "params": params}))
        r = await fut
        if "error" in r:
            raise RuntimeError(f"{method}: {r['error']}")
        return r.get("result", {})

    async def _read(self):
        async for msg in self.ws:
            d = json.loads(msg)
            if "id" in d and d["id"] in self.pend:
                self.pend.pop(d["id"]).set_result(d)
            elif d.get("method") == "Fetch.requestPaused":
                asyncio.create_task(self._paused(d["params"]))
            elif d.get("method") == "Runtime.exceptionThrown":
                e = d["params"]["exceptionDetails"]
                text = (e.get("exception") or {}).get("description") or e.get("text", "")
                if "tailwind is not defined" not in text:      # the CDN is refused in replay mode: styling only
                    self.errors.append(text[:500])

    async def _paused(self, p):
        rid, url = p["requestId"], p["request"]["url"]
        try:
            if is_local(url):
                self.local.append(url)
                if self.mode == "record" and "responseStatusCode" in p:
                    await self.call("Fetch.continueResponse", requestId=rid)
                else:
                    await self.call("Fetch.continueRequest", requestId=rid)
                return
            if self.mode == "record":
                if "responseStatusCode" not in p:
                    await self.call("Fetch.continueRequest", requestId=rid); return
                try:
                    status = p["responseStatusCode"]
                    if 200 <= status < 300 and not url.startswith(("https://cdn.tailwindcss.com", "https://cdnjs.cloudflare.com", "https://unpkg.com", "https://fonts.googleapis.com", "https://fonts.gstatic.com")):
                        body = await self.call("Fetch.getResponseBody", requestId=rid)
                        raw = base64.b64decode(body["body"]) if body.get("base64Encoded") else body["body"].encode()
                        ctype = next((h["value"] for h in p.get("responseHeaders", []) if h["name"].lower() == "content-type"), "application/json")
                        self.net[url] = {"status": status, "type": ctype, "body": raw.decode("utf-8", "replace")}
                finally:
                    await self.call("Fetch.continueResponse", requestId=rid)      # never leave a request hanging
                return
            hit = self.net.get(url)
            if hit is None:
                self.refused.add(url.split("?")[0])
                await self.call("Fetch.failRequest", requestId=rid, errorReason="BlockedByClient")
                return
            await self.call("Fetch.fulfillRequest", requestId=rid, responseCode=hit["status"],
                            responseHeaders=[{"name": "Content-Type", "value": hit["type"]}, {"name": "Access-Control-Allow-Origin", "value": "*"}],
                            body=base64.b64encode(hit["body"].encode()).decode())
        except Exception as e:      # the page may have moved on
            self.errors.append(f"[harness] {url}: {e}")

    async def goto(self, url, settle=1.0):
        await self.call("Page.navigate", url=url)
        await asyncio.sleep(settle)

    async def js(self, expr, timeout=180):
        r = await asyncio.wait_for(self.call("Runtime.evaluate", expression=expr, awaitPromise=True, returnByValue=True), timeout)
        if "exceptionDetails" in r:
            raise RuntimeError((r["exceptionDetails"].get("exception") or {}).get("description") or r["exceptionDetails"].get("text"))
        return r.get("result", {}).get("value")

    async def wait_for(self, cond, timeout=120, every=0.5):
        t0 = time.time()
        while time.time() - t0 < timeout:
            try:
                if await self.js(f"(() => {{ try {{ return !!({cond}); }} catch (e) {{ return false; }} }})()", 10):
                    return True
            except Exception:
                pass
            await asyncio.sleep(every)
        raise TimeoutError(f"waited {timeout}s for: {cond}")


class StaticServer:
    """python -m http.server on a free port, serving the repository (the no-server copy of CyberView)."""

    def __init__(self, root):
        self.root, self.port = root, free_port()

    def __enter__(self):
        self.proc = subprocess.Popen(["python3", "-m", "http.server", str(self.port), "--bind", "127.0.0.1", "--directory", self.root],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{self.port}/index.html"); break
            except Exception:
                time.sleep(0.1)
        return f"http://127.0.0.1:{self.port}"

    def __exit__(self, *a):
        self.proc.terminate()


def repo_root():
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def here(*p):
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), *p)
