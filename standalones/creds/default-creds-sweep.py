#!/usr/bin/env python3
"""default-creds-sweep.py — try default creds across 28+ admin portals.

Reads target list of ip:port (or url) and a product catalog. For each target:
  1. Fingerprint — does it match a known product?
  2. If yes, try every (user,pass) pair against the documented test_path
  3. Classify success based on either HTTP code or response regex
  4. Report findings with tier + next-step hint

Pure stdlib (urllib + json). Auth-respecting, low-rate by default.

Usage:
    default-creds-sweep.py --targets ip-ports.txt --catalog default-creds.json
    default-creds-sweep.py --target http://10.0.0.5:8161 --product 'ActiveMQ Web Console'
    default-creds-sweep.py --targets ip-ports.txt --threads 5 --delay 0.5
"""
from __future__ import annotations
import argparse, base64, json, os, re, ssl, sys, time, urllib.request, urllib.error
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------- ssl handling (skip cert verify for pentest convenience) ----------
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

# ---------- color ----------
def c(s, col):
    if not sys.stdout.isatty(): return s
    return {"R":"\033[1;31m","G":"\033[1;32m","Y":"\033[1;33m","C":"\033[1;36m","0":"\033[0m"}.get(col,"") + s + "\033[0m"


def http(url, method="GET", headers=None, data=None, timeout=8):
    """Returns (status, response-headers-as-lowercase-keys, body) or (0, {}, '')."""
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("User-Agent", "default-creds-sweep/1.0")
    for k, v in (headers or {}).items(): req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX) as r:
            body = r.read(65536).decode("utf-8", errors="replace")
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            return r.status, hdrs, body
    except urllib.error.HTTPError as e:
        body = e.read(65536).decode("utf-8", errors="replace") if e.fp else ""
        hdrs = {k.lower(): v for k, v in (e.headers or {}).items()}
        return e.code, hdrs, body
    except (urllib.error.URLError, TimeoutError, OSError, ssl.SSLError):
        return 0, {}, ""


def parse_target(t: str) -> list[str]:
    """Accept ip:port or http(s)://ip:port; expand bare ip:port to both http and https.

    IPv6 forms handled:
      [::1]:8080         -> http://[::1]:8080
      [2001:db8::1]      -> http://[2001:db8::1]:80  (no port → default 80)
      2001:db8::1        -> http://[2001:db8::1]:80  (bare v6 addr, no port)
    """
    if t.startswith(("http://","https://")):
        return [t.rstrip("/")]

    if t.startswith("["):
        # Bracketed IPv6 — e.g. [::1]:8080 or [2001:db8::1]
        close = t.find("]")
        if close == -1:
            print(f"[!] unparseable target (unmatched '['): {t!r}", file=sys.stderr)
            return []
        ip = t[1:close]
        rest = t[close + 1:]          # '' or ':8080'
        if rest.startswith(":") and rest[1:]:
            port = rest[1:]
        else:
            port = "80"
        host_part = f"[{ip}]"
    elif t.count(":") > 1:
        # Bare unbracketed IPv6 address (no port possible without brackets)
        ip = t
        port = "80"
        host_part = f"[{ip}]"
    elif ":" in t:
        # hostname:port or IPv4:port
        ip, port = t.rsplit(":", 1)
        host_part = ip
    else:
        ip, port = t, "80"
        host_part = ip

    # Choose http or https by port heuristic
    if port in ("443","8443","9443","4443","10443"):
        return [f"https://{host_part}:{port}"]
    if port in ("80","8080","8081","8000","8888","9000","3000","5000","5601","9200","15672","8161","8088","7001","7002","9990","4848","5050","5601","9090"):
        return [f"http://{host_part}:{port}"]
    return [f"http://{host_part}:{port}", f"https://{host_part}:{port}"]


def fingerprint(base_url: str, product: dict, timeout: int = 8) -> bool:
    fp = product.get("fingerprint_path", "/")
    regex = product.get("fingerprint_regex", "")
    status, hdrs, body = http(base_url + fp, timeout=timeout)
    if status == 0: return False
    haystack = body + " " + " ".join(f"{k}:{v}" for k, v in hdrs.items())
    if regex and re.search(regex, haystack, re.I):
        return True
    return False


def try_creds(base_url: str, product: dict, user: str, password: str,
              timeout: int = 8) -> tuple[bool, int, str]:
    path = product.get("test_path", "/")
    url = base_url + path
    body_re = product.get("success_re")
    code_ok = product.get("success_code")
    post_tpl = product.get("post")

    if post_tpl:
        data = post_tpl.replace("{USER}", user).replace("{PASS}", password).encode()
        if post_tpl.lstrip().startswith("{"):
            hdrs = {"Content-Type": "application/json"}
        else:
            hdrs = {"Content-Type": "application/x-www-form-urlencoded"}
        status, rhdrs, body = http(url, method="POST", headers=hdrs, data=data, timeout=timeout)
    else:
        auth = base64.b64encode(f"{user}:{password}".encode()).decode()
        hdrs = {"Authorization": f"Basic {auth}"}
        status, rhdrs, body = http(url, headers=hdrs, timeout=timeout)

    # Check response
    haystack = body + " " + " ".join(f"{k}:{v}" for k, v in rhdrs.items())
    if body_re and re.search(body_re, haystack, re.I):
        return True, status, "regex-match"
    if code_ok and status == code_ok and status != 401 and status != 403:
        return True, status, "code-match"
    return False, status, "no-match"


def scan_target(target: str, products: list[dict], delay: float, fingerprint_only: bool):
    found = []
    for base in parse_target(target):
        for product in products:
            try:
                if not fingerprint(base, product, timeout=6):
                    continue
            except Exception:
                continue

            tag = f"[{product['name']}]"
            print(c(f"  [?] {base}  matches {product['name']}", "C"), flush=True)

            if fingerprint_only:
                found.append({"url": base, "product": product["name"], "creds": None, "note": "fingerprint-only"})
                continue

            for cred in product.get("creds", []):
                if ":" not in cred: continue
                u, p = cred.split(":", 1)
                try:
                    ok, status, why = try_creds(base, product, u, p, timeout=6)
                except Exception:
                    continue
                time.sleep(delay)
                if ok:
                    print(c(f"  [!!] {base}  {product['name']}  {u}:{p}  ({why})", "R"), flush=True)
                    print(c(f"       -> {product.get('next_step','')}", "Y"), flush=True)
                    found.append({"url": base, "product": product["name"], "creds": f"{u}:{p}",
                                  "next_step": product.get("next_step",""), "status": status})
                    break  # one hit per product is enough
    return found


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--catalog", default=str(Path(__file__).resolve().parent / "default-creds.json"))
    ap.add_argument("--target", help="single ip:port or URL")
    ap.add_argument("--targets", help="file with one ip:port per line")
    ap.add_argument("--product", help="restrict to single product by name")
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--delay",   type=float, default=0.2, help="per-credential delay (per target)")
    ap.add_argument("--fingerprint-only", action="store_true", help="just identify products, don't try creds")
    ap.add_argument("--output",  default="findings.json")
    args = ap.parse_args()

    if args.threads < 1:
        print("[!] --threads must be >= 1", file=sys.stderr); return 2

    try:
        catalog = json.loads(Path(args.catalog).read_text())
        products = catalog["products"]
    except FileNotFoundError as e:
        print(f"[!] catalog unreadable: {e}", file=sys.stderr); return 2
    except json.JSONDecodeError as e:
        print(f"[!] catalog invalid JSON: {args.catalog}: {e}", file=sys.stderr); return 2
    except KeyError:
        print(f"[!] catalog missing 'products' key: {args.catalog}", file=sys.stderr); return 2
    if args.product:
        products = [p for p in products if p["name"].lower() == args.product.lower()]
        if not products:
            print("no matching product in catalog"); return 2

    targets = []
    if args.target: targets = [args.target]
    elif args.targets: targets = [l.strip() for l in Path(args.targets).read_text().splitlines() if l.strip() and not l.startswith("#")]
    else:
        print("--target or --targets required"); return 2

    print(c(f"[*] Sweeping {len(targets)} target(s) against {len(products)} product(s) with {args.threads} threads", "C"))
    all_findings = []
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = {ex.submit(scan_target, t, products, args.delay, args.fingerprint_only): t for t in targets}
        for f in as_completed(futs):
            try:
                all_findings.extend(f.result())
            except Exception as e:
                print(c(f"  [err] {futs[f]}: {e}", "Y"))

    if all_findings:
        print()
        print(c(f"=== {len(all_findings)} finding(s) ===", "G"))
        for f in all_findings:
            if f.get("creds"):
                print(c(f"  {f['url']:50s}  {f['product']:30s}  {f['creds']}", "G"))
            else:
                print(f"  {f['url']:50s}  {f['product']:30s}  (fingerprint only)")
    else:
        print(c("=== no findings ===", "Y"))

    Path(args.output).write_text(json.dumps(all_findings, indent=2))
    print(f"Findings written: {args.output}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
