#!/usr/bin/env python3
"""
ScamHound v2.0 — Scammer Recon & Tracking Toolkit
==================================================
Modules:
  1. phone    - Phone number recon (carrier, line type, footprinting)
  2. osint    - OSINT link generation + breach/scam-report checks
  3. tracker  - Self-hosted click tracker w/ live dashboard
  4. ipinfo   - IP geolocation + hosting/VPN/proxy detection
  5. report   - Compile findings into IC3 / bank fraud report
  6. email    - Email recon (breach check, disposable detection, gravatar)
  7. domain   - Scam domain recon (WHOIS, DNS, SSL age, archive check)
  8. crypto   - Crypto address tracing (BTC balance/tx via blockchain.info,
                ETH via etherscan if key provided)
  9. social   - Social media / messenger handle discovery (incl. Telegram bot check)
 10. combo    - Feed a phone + email + domain together; cross-correlate findings
 11. summary  - Merge all case JSON into one intel brief

Usage:
  python scamhound.py phone +18005550123
  python scamhound.py email someone@x.com
  python scamhound.py domain evil-bank-login.com
  python scamhound.py crypto bc1qxyz...
  python scamhound.py social somehandle
  python scamhound.py ipinfo 1.2.3.4
  python scamhound.py tracker --host 0.0.0.0 --port 80 --baits invoice.pdf
  python scamhound.py combo --phone +18005550123 --email x@y.com --domain evil.com
  python scamhound.py summary
  python scamhound.py report --case mycase
"""

import argparse
import json
import os
import re
import socket
import sqlite3
import ssl
import sys
import time
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

VERSION = "2.0"
CASE_DIR = Path("cases")
TRACKER_DB = "tracker.db"
CASE_DB = CASE_DIR / "cases.db"

# ----------------------------------------------------------------------------
# Case management
# ----------------------------------------------------------------------------
def case_path(case: str) -> Path:
    d = CASE_DIR / case
    d.mkdir(parents=True, exist_ok=True)
    return d

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def save_case(case: str, name: str, data: dict):
    """Write JSON file + index into SQLite case DB."""
    try:
        p = case_path(case) / f"{name}.json"
        p.write_text(json.dumps(data, indent=2))
        log(f"Saved: {p}")
        _db_index(case, name, data)
    except Exception as e:
        log(f"save_case failed for {name}: {e}", "!")

def _db_index(case: str, name: str, data: dict):
    """Lightweight cross-reference index so 'combo' can correlate findings."""
    try:
        with sqlite3.connect(CASE_DB) as db:
            db.execute("""CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case TEXT, module TEXT, ref TEXT, ts TEXT, data TEXT)""")
            module = name.split("_", 1)[0]
            ref = ""
            if isinstance(data, dict):
                for k in ("e164", "email", "domain", "ip", "handle", "address", "input"):
                    if k in data:
                        ref = str(data[k]); break
                    if "parsed" in data and isinstance(data["parsed"], dict) and "e164" in data["parsed"]:
                        ref = str(data["parsed"]["e164"]); break
            db.execute("INSERT INTO findings (case,module,ref,ts,data) VALUES (?,?,?,?,?)",
                       (case, module, ref, utc_now(), json.dumps(data)))
    except Exception as e:
        log(f"case-db index failed: {e}", "!")

def log(msg, level="+"):
    icons = {"+": "[+]", "!": "[!]", "*": "[*]", "★": "[★]", "-": "[-]"}
    print(f"{icons.get(level, level)} [{datetime.now().strftime('%H:%M:%S')}] {msg}")

# ----------------------------------------------------------------------------
# Network helpers (stdlib only, fully wrapped)
# ----------------------------------------------------------------------------
def http_get(url: str, headers: dict = None, timeout: int = 12) -> dict:
    """GET a URL, return parsed JSON if possible else text. Never raises."""
    out = {"ok": False, "status": 0, "json": None, "text": ""}
    try:
        req = urllib.request.Request(url, headers=headers or {"User-Agent": f"ScamHound/{VERSION}"})
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            out["status"] = r.status
            raw = r.read(200_000).decode("utf-8", "replace")
            out["text"] = raw
            try:
                out["json"] = json.loads(raw)
            except Exception:
                pass
            out["ok"] = True
    except Exception as e:
        out["error"] = str(e)
    return out

def fetch_json(url: str, headers: dict = None, timeout: int = 12):
    r = http_get(url, headers, timeout)
    return r.get("json")

# ----------------------------------------------------------------------------
# Module 1: PHONE RECON
# ----------------------------------------------------------------------------
def phone_recon(number: str, case: str):
    log(f"Recon for {number}")
    result = {"module": "phone", "input": number, "timestamp": utc_now(), "sources": {}}

    # --- Local parsing (install: pip install phonenumbers) ---
    try:
        import phonenumbers
        from phonenumbers import geocoder, carrier, timezone as pn_tz
        n = phonenumbers.parse(number, None)
        valid = phonenumbers.is_valid_number(n)
        if not valid:
            log("Number appears INVALID — likely spoofed/VoIP or typo", "!")
        e164 = phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.E164)
        result["parsed"] = {
            "e164": e164,
            "valid": valid,
            "possible": phonenumbers.is_possible_number(n),
            "country": phonenumbers.region_code_for_number(n),
            "region_guess": str(geocoder.description_for_number(n, "en")),
            "carrier_guess": carrier.name_for_number(n, "en"),
            "timezones": list(pn_tz.timezones_for_number(n)),
            "number_type": str(phonenumbers.number_type(n)),
        }
        log(f"E.164: {e164} | Type: {result['parsed']['number_type']}")
        number = e164
    except ImportError:
        log("phonenumbers not installed (pip install phonenumbers) — using raw number", "!")
    except Exception as e:
        log(f"phonenumbers parse error: {e}", "!")

    # --- numverify (optional, free key) ---
    api_key = os.environ.get("NUMVERIFY_KEY")
    if api_key:
        d = fetch_json(f"https://apilayer.net/api/validate?access_key={api_key}&number={number.lstrip('+')}")
        if d:
            result["sources"]["numverify"] = d
            log(f"numverify: carrier={d.get('carrier')} line={d.get('line_type')} "
                f"valid={d.get('valid')}", "*")
        else:
            log("numverify lookup failed", "!")

    # --- OSINT search links ---
    q = number.replace(" ", "")
    digits = q.lstrip("+")
    result["osint_links"] = {
        "google_scam_reports": f'https://www.google.com/search?q="{q}"+(scam+OR+fraud+OR+report)',
        "bing_scam_reports":   f'https://www.bing.com/search?q="{q}"+(scam+OR+fraud)',
        "duckduckgo":          f'https://duckduckgo.com/?q="{q}"+scam',
        "truecaller":          f"https://www.truecaller.com/search/us/{digits}",
        "who_calls_me":        f"https://who-calls.me.uk/search?q={q}",
        "800notes":            f"https://800notes.com/Phone.aspx/1-{digits}",
        "tellows":             f"https://www.tellows.com/num/{digits}",
        "sync.me":             f"https://sync.me/search/?number={q}",
        "whatsapp_check":      f"https://wa.me/{digits}",
        "telegram":            f"https://t.me/+{digits}",
        "facebook":            f"https://www.facebook.com/search/top?q={q}",
        "paste_search":        f'https://www.google.com/search?q="{q}"+(site:pastebin.com+OR+site:ghostbin.com)',
        "leak_lookup":         f"https://leak-lookup.com/search?query={digits}",
    }
    print("\nOSINT links (open manually or use --open):")
    for k, v in result["osint_links"].items():
        print(f"  {k:22s} {v}")

    if "--open" in sys.argv:
        import webbrowser
        for v in result["osint_links"].values():
            webbrowser.open(v)
            time.sleep(0.4)

    save_case(case, f"phone_{number.lstrip('+')}", result)
    return result

# ----------------------------------------------------------------------------
# Module 2: EMAIL RECON
# ----------------------------------------------------------------------------
DISPOSABLE_DOMAINS = {
    "mailinator.com","10minutemail.com","guerrillamail.com","yopmail.com",
    "tempmail.com","temp-mail.org","throwawaymail.com","getnada.com",
    "trashmail.com","sharklasers.com","dispostable.com","maildrop.cc",
}

def email_recon(email: str, case: str):
    email = email.strip().lower()
    log(f"Email recon: {email}")
    result = {"module": "email", "email": email, "timestamp": utc_now()}

    if not re.match(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$", email):
        log("Not a valid email format", "!")
        save_case(case, f"email_{re.sub(r'[^a-z0-9._-]','_',email)}", result)
        return result

    local, domain = email.split("@", 1)
    result["local"] = local
    result["domain"] = domain
    result["disposable"] = domain in DISPOSABLE_DOMAINS
    if result["disposable"]:
        log("Domain is a DISPOSABLE email provider — burner identity", "!")

    # --- MX records (is the mailbox domain real?) ---
    try:
        import subprocess
        p = subprocess.run(["nslookup", "-type=MX", domain], capture_output=True,
                           text=True, timeout=10)
        mx = [l.strip() for l in p.stdout.splitlines() if "mail exchanger" in l.lower()]
        result["mx_records"] = mx
        if mx:
            log(f"MX records found ({len(mx)}) — domain accepts mail", "*")
            first = mx[0].split(" = ")[-1] if " = " in mx[0] else ""
            if any(x in first for x in ("mailgun", "sendgrid", "amazonses", "outlook", "google")):
                log(f"Mail provider hint: {first}", "*")
        else:
            log("No MX records — domain may not actually receive mail", "!")
    except FileNotFoundError:
        log("nslookup not available — skipping MX check", "-")
    except Exception as e:
        log(f"MX check failed: {e}", "!")

    # --- Have I Been Pwned (optional key) ---
    hibp_key = os.environ.get("HIBP_KEY")
    if hibp_key:
        r = http_get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}?truncateResponse=false",
            headers={"hibp-api-key": hibp_key, "User-Agent": f"ScamHound/{VERSION}"})
        if r["ok"]:
            result["breaches"] = r.get("json") or []
            log(f"Found in {len(result['breaches'])} breach(es): "
                + ", ".join(b.get("Title","?") for b in result["breaches"][:5]), "*")
        elif r["status"] == 404:
            log("Not found in any breach (HIBP)", "-")
        else:
            log(f"HIBP check failed: {r.get('error')}", "!")

    # --- Breach forums / paste OSINT links ---
    result["osint_links"] = {
        "google_local":      f'https://www.google.com/search?q="{local}"+(scam+OR+fraud)',
        "google_email":      f'https://www.google.com/search?q="{email}"',
        "paste_search":      f'https://www.google.com/search?q="{email}"+(site:pastebin.com+OR+site:ghostbin.com)',
        "leakcheck":         f"https://leakcheck.io/search?query={email}",
        "have_i_been_pwned": f"https://haveibeenpwned.com/account/{email}",
        "gravatar":          f"https://www.gravatar.com/{hashlib_sha256(email)}",
        "holehe":            f"https://github.com/megadose/holehe (local tool — run: holehe {email})",
        "epieos":            f"https://epieos.com/?q={urllib.parse.quote(email)}",
        "intelx":            f"https://intelx.io/?s={email}",
    }
    print("\nOSINT links:")
    for k, v in result["osint_links"].items():
        print(f"  {k:22s} {v}")

    # --- Gravatar profile (if registered, often leaks name/avatars) ---
    gh = hashlib_sha256(email)
    r = http_get(f"https://www.gravatar.com/{gh}.json", timeout=8)
    if r["ok"] and r.get("json"):
        try:
            entry = r["json"].get("entry", [{}])[0]
            result["gravatar"] = {
                "hash": gh,
                "display_name": entry.get("displayName"),
                "about": entry.get("aboutMe"),
                "urls": [u.get("value") for u in entry.get("urls", [])],
            }
            log(f"Gravatar profile found: {entry.get('displayName')}", "*")
        except Exception:
            pass

    save_case(case, f"email_{email.replace('@','_at_').replace('.','_')}", result)
    return result

def hashlib_sha256(s: str) -> str:
    import hashlib
    return hashlib.sha256(s.strip().lower().encode()).hexdigest()

# ----------------------------------------------------------------------------
# Module 3: DOMAIN RECON
# ----------------------------------------------------------------------------
def domain_recon(domain: str, case: str):
    domain = domain.strip().lower().replace("http://", "").replace("https://", "").rstrip("/")
    log(f"Domain recon: {domain}")
    result = {"module": "domain", "domain": domain, "timestamp": utc_now()}

    # --- DNS A record ---
    try:
        result["a_records"] = sorted({ai[4][0] for ai in socket.getaddrinfo(domain, 443, socket.AF_INET)})
        log(f"A records: {', '.join(result['a_records'])}", "*")
    except Exception as e:
        log(f"DNS resolution failed: {e}", "!")
        result["a_records"] = []

    # --- WHOIS (uses python-whois if available, else RDAP fallback) ---
    try:
        import whois
        w = whois.whois(domain)
        result["whois"] = {
            k: str(v)[:400] for k, v in (w.items() if hasattr(w, "items") else [])
            if v and k in ("domain_name","registrar","creation_date","expiration_date",
                           "name_servers","registrant_name","registrant_email","org","country")
        }
        log("python-whois data retrieved", "*")
    except ImportError:
        # RDAP is a free, no-key standard WHOIS-over-HTTP
        rdap = fetch_json(f"https://rdap.org/domain/{domain}")
        if rdap:
            result["rdap"] = {
                "registrar": next((e.get("vcardArray",[None,[]])[1][3].get("value")
                                   for e in rdap.get("entities", [])
                                   if "registrar" in e.get("roles", [])
                                   and e.get("vcardArray")), "unknown"),
                "events": {e["eventAction"]: e["eventDate"] for e in rdap.get("events", [])},
                "nameservers": [ns["ldhName"] for ns in rdap.get("nameservers", [])],
            }
            log("RDAP record retrieved (no python-whois installed)", "*")
        else:
            log("No WHOIS/RDAP info available", "!")
    except Exception as e:
        log(f"WHOIS failed: {e}", "!")

    # --- Registration age heuristic ---
    created = None
    try:
        for k in ("creation_date",):
            v = result.get("whois", {}).get(k)
            if v: created = v; break
        if not created and result.get("rdap"):
            created = result["rdap"]["events"].get("registration")
        if created:
            from datetime import datetime as _dt
            try:
                c = _dt.fromisoformat(str(created).replace("Z","+00:00"))
                age_days = (datetime.now(timezone.utc) - c).days
                result["domain_age_days"] = age_days
                if age_days < 30:
                    log(f"Domain registered {age_days} days ago — VERY NEW, classic scam marker", "!")
                elif age_days < 180:
                    log(f"Domain registered {age_days} days ago — young", "!")
                else:
                    log(f"Domain age: {age_days} days", "*")
            except Exception:
                pass
    except Exception:
        pass

    # --- TLS cert (self-signed / expiring soon / short validity = scam marker) ---
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as s:
                cert = s.getpeercert(binary_form=False) or {}
        result["tls"] = {k: v for k, v in cert.items()
                         if k in ("subject","issuer","notAfter","notBefore","subjectAltName")}
        log(f"TLS issuer: {dict(cert.get('issuer', [])[0] if cert.get('issuer') else {})}", "*")
    except Exception as e:
        log(f"TLS handshake failed: {e}", "!")

    # --- Wayback Machine (was the site repurposed?) ---
    wb = fetch_json(f"https://archive.org/wayback/available?url={domain}", timeout=8)
    if wb and wb.get("archived_snapshots"):
        snap = wb["archived_snapshots"].get("closest", {})
        result["wayback"] = snap
        if snap:
            log(f"Oldest snapshot: {snap.get('timestamp')} — {snap.get('url')}", "*")

    # --- IP enrichment of resolved IPs ---
    for ip in result["a_records"][:3]:
        log(f"Enriching {ip}", "-")
        ip_info(ip, case)

    # --- OSINT links ---
    result["osint_links"] = {
        "virustotal":   f"https://www.virustotal.com/gui/domain/{domain}",
        "urlscan":      f"https://urlscan.io/search/#{domain}",
        "crt_sh":       f"https://crt.sh/?q=%25.{domain}",
        "archive_today":f"https://archive.ph/{domain}*",
        "whois_xml":    f"https://www.whois.com/whois/{domain}",
        "shodan":       f"https://www.shodan.io/search?query=hostname%3A{domain}",
        "google_cache": f"https://webcache.googleusercontent.com/search?q=cache:{domain}",
    }
    print("\nOSINT links:")
    for k, v in result["osint_links"].items():
        print(f"  {k:22s} {v}")

    save_case(case, f"domain_{domain.replace('.','_')}", result)
    return result

# ----------------------------------------------------------------------------
# Module 4: CRYPTO ADDRESS TRACING
# ----------------------------------------------------------------------------
def crypto_recon(address: str, case: str):
    address = address.strip()
    log(f"Crypto recon: {address}")
    result = {"module": "crypto", "address": address, "timestamp": utc_now()}

    # --- Type detection ---
    if address.startswith("bc1") or address.startswith(("1", "3")) and len(address) in range(26, 36):
        chain = "BTC"
    elif address.startswith("0x") and len(address) == 42:
        chain = "ETH"
    elif address.startswith(("L", "M")) and len(address) in range(26, 35):
        chain = "LTC"
    elif address.startswith("X") and len(address) in (95, 106):
        chain = "XMR"
    elif address.startswith("T") and len(address) == 34:
        chain = "TRX"
    else:
        chain = "UNKNOWN"
    result["chain"] = chain
    log(f"Detected chain: {chain}", "*")

    # --- BTC via blockchain.info (free, no key) ---
    if chain == "BTC":
        d = fetch_json(f"https://blockchain.info/rawaddr/{address}", timeout=15)
        if d:
            result["btc"] = {
                "total_received_btc": d.get("total_received", 0) / 1e8,
                "total_sent_btc": d.get("total_sent", 0) / 1e8,
                "final_balance_btc": d.get("final_balance", 0) / 1e8,
                "tx_count": d.get("n_tx"),
                "first_seen": (d.get("txs") or [{}])[-1].get("time"),
                "recent_tx": [{"hash": t.get("hash"), "time": t.get("time"),
                               "in": len(t.get("inputs", [])), "out": len(t.get("out", []))}
                              for t in (d.get("txs") or [])[:10]],
            }
            b = result["btc"]
            log(f"BTC balance: {b['final_balance_btc']:.8f} | txs: {b['tx_count']}", "*")
            if b["tx_count"] == 0:
                log("Never used — freshly generated wallet", "!")
        else:
            log("blockchain.info lookup failed", "!")
        result["osint_links"] = {
            "blockchair":    f"https://blockchair.com/bitcoin/address/{address}",
            "btc_explorer":  f"https://www.blockchain.com/explorer/addresses/btc/{address}",
            "ogle_search":   f'https://www.google.com/search?q="{address}"',
            "chainabuse":    f"https://www.chainabuse.com/address/{address}",
            "bitcoinabuse":  f"https://www.chainalysis.com/ (paid)",
        }

    # --- ETH via Etherscan (optional free key) ---
    if chain == "ETH":
        eth_key = os.environ.get("ETHERSCAN_KEY")
        if eth_key:
            bal = fetch_json(f"https://api.etherscan.io/api?module=account&action=balance&address={address}&tag=latest&apikey={eth_key}")
            txs = fetch_json(f"https://api.etherscan.io/api?module=account&action=txlist&address={address}&startblock=0&endblock=99999999&sort=desc&page=1&offset=10&apikey={eth_key}")
            if bal and bal.get("result"):
                wei = int(bal["result"])
                result["eth"] = {"balance_eth": wei / 1e18}
                log(f"ETH balance: {result['eth']['balance_eth']:.6f}", "*")
            if txs and txs.get("result"):
                result["eth"]["recent_tx"] = txs["result"][:10]
        else:
            log("Set ETHERSCAN_KEY for live ETH data (free tier)", "-")
        result["osint_links"] = {
            "etherscan":     f"https://etherscan.io/address/{address}",
            "blockchair":    f"https://blockchair.com/ethereum/address/{address}",
            "ogle_search":   f'https://www.google.com/search?q="{address}"',
            "chainabuse":    f"https://www.chainabuse.com/address/{address}",
        }

    if chain == "XMR":
        log("Monero is privacy-preserving — use a view-key explorer or the victim's tx hash", "-")
        result["osint_links"] = {
            "xmr_explorer":  f"https://xmrchain.net/search?value={address}",
            "ogle_search":   f'https://www.google.com/search?q="{address}"',
        }

    if chain == "TRX":
        result["osint_links"] = {
            "tronscan":      f"https://tronscan.org/#/address/{address}",
            "ogle_search":   f'https://www.google.com/search?q="{address}"',
        }
        log("TRC-20 USDT is the #1 scam rail — pull tx list from tronscan manually", "!")

    for k, v in (result.get("osint_links") or {}).items():
        print(f"  {k:22s} {v}")

    save_case(case, f"crypto_{address[:16]}", result)
    return result

# ----------------------------------------------------------------------------
# Module 5: SOCIAL / HANDLE DISCOVERY
# ----------------------------------------------------------------------------
SOCIAL_SITES = [
    ("twitter",   "https://twitter.com/{h}"),
    ("instagram", "https://www.instagram.com/{h}/"),
    ("telegram",  "https://t.me/{h}"),
    ("github",    "https://github.com/{h}"),
    ("reddit",    "https://www.reddit.com/user/{h}"),
    ("tiktok",    "https://www.tiktok.com/@{h}"),
    ("youtube",   "https://www.youtube.com/@{h}"),
    ("facebook",  "https://www.facebook.com/{h}"),
    ("linkedin",  "https://www.linkedin.com/in/{h}"),
    ("vk",        "https://vk.com/{h}"),
    ("medium",    "https://medium.com/@{h}"),
    ("discord",   "https://discord.com/users/{h}"),
    ("mastodon",  "https://mastodon.social/@{h}"),
]

def social_recon(handle: str, case: str):
    handle = handle.strip().lstrip("@")
    log(f"Social recon for handle: {handle}")
    result = {"module": "social", "handle": handle, "timestamp": utc_now(), "hits": []}

    for name, tpl in SOCIAL_SITES:
        url = tpl.format(h=handle)
        r = http_get(url, timeout=6)
        exists = r["ok"] and r["status"] == 200
        # Some sites return 200 for "not found" pages — filter by content
        if exists:
            body = (r.get("text") or "").lower()
            if name == "instagram" and ("page not found" in body or "sorry, this page isn" in body):
                exists = False
            if name == "twitter" and ("page doesn" in body or "doesn’t exist" in body):
                exists = False
            if name == "github" and "not found" in body and len(body) < 3000:
                exists = False
        status = "EXISTS" if exists else "—"
        if exists:
            result["hits"].append(name)
            log(f"  {name:12s} {status}", "*")
        else:
            log(f"  {name:12s} {status}", "-")
        print(f"    {name:12s} {url}")

    result["osint_links"] = {
        "namechk_style":   f"https://namechk.com/{handle}",
        "instant_username":f"https://instantusername.com/#/{handle}",
        "sherlock":        f"https://github.com/sherlock-project/sherlock (local: sherlock {handle})",
        "google":          f'https://www.google.com/search?q="{handle}"',
        "whatsmyname":     f"https://whatsmyname.app/?q={handle}",
    }
    print("\nOSINT links:")
    for k, v in result["osint_links"].items():
        print(f"  {k:22s} {v}")

    save_case(case, f"social_{handle}", result)
    return result

# ----------------------------------------------------------------------------
# Module 6: IP ENRICHMENT
# ----------------------------------------------------------------------------
def ip_info(ip: str, case: str):
    log(f"IP lookup: {ip}")
    result = {"module": "ip", "ip": ip, "timestamp": utc_now()}

    d = fetch_json(f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query")
    if d and d.get("status") == "success":
        result["geo"] = d
        tags = []
        if d.get("hosting"): tags.append("HOSTING/VPS ← scammer on rented VM")
        if d.get("proxy"):   tags.append("PROXY/VPN in use")
        if d.get("mobile"):  tags.append("MOBILE carrier")
        log(f"{d['city']}, {d['country']} | ISP: {d['isp']} | AS: {d['as']}")
        log("Classification: " + ("; ".join(tags) or "RESIDENTIAL/BUSINESS"), "*")
        if d.get("reverse"):
            log(f"PTR: {d['reverse']} — check for call-center/VoIP keywords", "*")
    else:
        log(f"ip-api failed: {d.get('message', 'unknown') if d else 'no response'}", "!")

    abuse_key = os.environ.get("ABUSEIPDB_KEY")
    if abuse_key:
        r = http_get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
                     headers={"Key": abuse_key, "Accept": "application/json"})
        if r["ok"] and r.get("json"):
            dd = r["json"]["data"]
            result["abuseipdb"] = {
                "abuse_confidence": dd["abuseConfidenceScore"],
                "total_reports": dd["totalReports"],
                "is_tor": dd.get("isTor"),
                "usage_type": dd.get("usageType"),
            }
            log(f"AbuseIPDB confidence: {dd['abuseConfidenceScore']}% "
                f"({dd['totalReports']} reports)", "*")
        else:
            log("AbuseIPDB check failed", "!")

    # --- Shodan (optional free key) — what ports/services does the host expose? ---
    shodan_key = os.environ.get("SHODAN_KEY")
    if shodan_key:
        s = fetch_json(f"https://api.shodan.io/shodan/host/{ip}?key={shodan_key}")
        if s:
            result["shodan"] = {
                "ports": s.get("ports"),
                "hostnames": s.get("hostnames"),
                "org": s.get("org"),
                "vulns": list((s.get("vulns") or {}).keys()),
                "last_update": s.get("last_update"),
            }
            log(f"Shodan ports: {s.get('ports')}", "*")

    save_case(case, f"ip_{ip.replace('.', '_')}", result)
    return result

# ----------------------------------------------------------------------------
# Module 7: COMBO — cross-correlate phone + email + domain + crypto
# ----------------------------------------------------------------------------
def combo_recon(case: str, phone=None, email=None, domain=None, crypto=None, handle=None):
    log("COMBO recon — running all provided modules", "*")
    refs = []
    if phone:
        r = phone_recon(phone, case)
        refs.append(r)
    if email:
        r = email_recon(email, case)
        refs.append(r)
    if domain:
        r = domain_recon(domain, case)
        refs.append(r)
    if crypto:
        r = crypto_recon(crypto, case)
        refs.append(r)
    if handle:
        r = social_recon(handle, case)
        refs.append(r)

    # --- Cross-reference: does any shared IP / name / org show up? ---
    log("Cross-referencing findings…", "*")
    ips, names, orgs = set(), set(), set()
    for r in refs:
        if r.get("module") == "domain":
            for ip in r.get("a_records", []): ips.add(ip)
            for k in ("org", "registrant_name"):
                v = r.get("whois", {}).get(k)
                if v: names.add(str(v)[:100])
        if r.get("module") == "ip":
            g = r.get("geo", {})
            if g.get("isp"): orgs.add(g["isp"])
            if g.get("org"): orgs.add(g["org"])

    if ips:
        log(f"IPs tied to this identity: {', '.join(sorted(ips))}", "★")
    if names:
        log(f"Registrant/org names: {', '.join(sorted(names))}", "★")
    if orgs:
        log(f"Hosting orgs: {', '.join(sorted(orgs))}", "★")

    # --- Shared infra check: any IP used by both domain AND phone's carrier? ---
    shared = ips & orgs  # crude but useful hint
    if shared:
        log("OVERLAP between domain IPs and hosting orgs — same infra likely", "!")

    summary = {
        "module": "combo",
        "timestamp": utc_now(),
        "inputs": {"phone": phone, "email": email, "domain": domain,
                   "crypto": crypto, "handle": handle},
        "ips": sorted(ips),
        "orgs": sorted(orgs),
        "registrant_names": sorted(names),
        "modules_run": [r.get("module") for r in refs],
    }
    save_case(case, "combo_summary", summary)
    return summary

# ----------------------------------------------------------------------------
# Module 8: SUMMARY — merge case dir into one intel brief
# ----------------------------------------------------------------------------
def build_summary(case: str):
    d = case_path(case)
    files = sorted(d.glob("*.json"))
    if not files:
        log("No findings in this case", "!")
        return
    merged = {"case": case, "generated": utc_now(), "version": VERSION, "findings": {}}
    for f in files:
        try:
            merged["findings"][f.stem] = json.loads(f.read_text())
        except Exception as e:
            log(f"Skipping unreadable file {f.name}: {e}", "!")
    out = d / "SUMMARY.json"
    out.write_text(json.dumps(merged, indent=2))
    log(f"Merged summary: {out}", "*")
    log(f"Modules present: {', '.join(sorted(merged['findings'].keys()))}")
    return merged

# ----------------------------------------------------------------------------
# Module 9: CLICK TRACKER + DASHBOARD
# ----------------------------------------------------------------------------
TRACKER_HTML = """<!DOCTYPE html><html><head><title>ScamHound Tracker</title>
<meta http-equiv="refresh" content="10"><style>
body{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:2em}
table{border-collapse:collapse;width:100%}td,th{border:1px solid #30363d;padding:6px 12px;text-align:left}
th{background:#161b22}h1{color:#58a6ff}</style></head><body>
<h1>ScamHound v{V} — Live Hits</h1><table><tr>
<th>Time (UTC)</th><th>IP</th><th>Geo</th><th>ISP</th><th>Hosting?</th><th>Proxy?</th>
<th>User-Agent</th><th>Referer</th><th>Bait</th></tr>
{rows}</table></body></html>"""

def init_tracker_db():
    with sqlite3.connect(TRACKER_DB) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS hits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, ip TEXT, ua TEXT, referer TEXT,
            bait TEXT, geo TEXT)""")

def geo_lookup(ip):
    return fetch_json(f"http://ip-api.com/json/{ip}?fields=city,country,isp,hosting,proxy", timeout=5) or {}

def run_tracker(host, port, baits, case):
    from flask import Flask, request, send_file, abort
    from datetime import datetime as dt

    app = Flask(__name__)
    log(f"Tracker up — bait endpoints: {', '.join('/' + b for b in baits)}")
    log(f"Dashboard: http://{host}:{port}/dashboard")

    def record(bait):
        try:
            ip = (request.headers.get("X-Forwarded-For", request.remote_addr or "?")
                  .split(",")[0].strip())
            ua = request.headers.get("User-Agent", "")
            ref = request.headers.get("Referer", "")
            geo = geo_lookup(ip)
            with sqlite3.connect(TRACKER_DB) as db:
                db.execute("INSERT INTO hits (ts,ip,ua,referer,bait,geo) VALUES (?,?,?,?,?,?)",
                           (dt.now(dt.timezone.utc).isoformat(), ip, ua, ref, bait, json.dumps(geo)))
                db.commit()
            log(f"HIT on /{bait} <- {ip} ({geo.get('city','?')}, {geo.get('country','?')}) "
                f"ISP={geo.get('isp','?')} hosting={geo.get('hosting')} proxy={geo.get('proxy')}", "★")
            save_case(case, f"hit_{dt.now(dt.timezone.utc).strftime('%H%M%S')}_{ip.replace('.','_')}",
                      {"ip": ip, "ua": ua, "referer": ref, "bait": bait, "geo": geo})
        except Exception as e:
            log(f"record failed: {e}", "!")

    for bait in baits:
        payload = Path(bait)
        endpoint = f"bait_{re.sub(r'[^a-zA-Z0-9_]', '_', bait)}"
        def _bait(b=bait, p=payload):
            record(b)
            if p.exists():
                return send_file(p)
            abort(404)
        app.add_url_rule(f"/{bait}", endpoint, _bait, methods=["GET"])

    @app.route("/pixel.gif", endpoint="pixel")
    def _pixel():
        record("pixel.gif")
        gif = (b"\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00"
               b"\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00"
               b"\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;")
        return app.response_class(gif, mimetype="image/gif")

    @app.route("/dashboard")
    def _dash():
        with sqlite3.connect(TRACKER_DB) as db:
            rows = db.execute("SELECT ts,ip,geo,ua,referer,bait FROM hits ORDER BY id DESC").fetchall()
        trs = ""
        for ts, ip, geo, ua, ref, bait in rows:
            try:
                g = json.loads(geo or "{}")
            except Exception:
                g = {}
            trs += (f"<tr><td>{ts}</td><td>{ip}</td><td>{g.get('city','?')}, {g.get('country','?')}</td>"
                    f"<td>{g.get('isp','?')}</td><td>{g.get('hosting','?')}</td><td>{g.get('proxy','?')}</td>"
                    f"<td>{ua[:60]}</td><td>{ref[:40]}</td><td>{bait}</td></tr>")
        return TRACKER_HTML.replace("{rows}", trs).replace("{V}", VERSION)

    app.run(host=host, port=port)

# ----------------------------------------------------------------------------
# Module 10: REPORT GENERATION — IC3 / bank fraud submission
# ----------------------------------------------------------------------------
def build_report(case):
    d = case_path(case)
    findings = sorted(d.glob("*.json"))
    if not findings:
        log("No findings in this case", "!")
        return
    lines = [f"# ScamHound v{VERSION} Case Report: {case}",
             f"Generated: {utc_now()}", ""]
    for f in findings:
        lines += [f"## {f.stem}", "```json", f.read_text(), "```", ""]
    lines += ["## Recommended reporting channels",
              "- IC3 (US): https://www.ic3.gov — file complaint with all evidence",
              "- Receiving bank's fraud department (if you have mule account details)",
              "- FCC spoofing complaints: https://consumercomplaints.fcc.gov",
              "- FTC: https://reportfraud.ftc.gov",
              "- If target country differs: local cybercrime portal (e.g., cybercrime.gov.in)",
              "- Crypto scams: report to the exchange receiving the funds + IC3",
              "- Domain abuse: registrar abuse email from WHOIS + hoster's abuse@ "]
    out = d / "REPORT.md"
    out.write_text("\n".join(lines))
    log(f"Report written: {out}", "*")

# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------
def main():
    p = argparse.ArgumentParser(description=f"ScamHound v{VERSION} — scammer recon & tracking")
    p.add_argument("module", choices=["phone", "email", "domain", "crypto", "social",
                                      "ipinfo", "combo", "summary", "tracker", "report"])
    p.add_argument("target", nargs="?", help="phone number / email / domain / crypto addr / IP / handle")
    p.add_argument("--case", default=f"case_{datetime.now().strftime('%Y%m%d')}")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=80)
    p.add_argument("--baits", nargs="+", default=["invoice.pdf", "statement.docx", "photo.jpg"])
    p.add_argument("--phone")
    p.add_argument("--email")
    p.add_argument("--domain")
    p.add_argument("--crypto")
    p.add_argument("--handle")
    args = p.parse_args()

    if args.module == "tracker":
        init_tracker_db()
        run_tracker(args.host, args.port, args.baits, args.case)
    elif args.module == "phone":
        if not args.target: sys.exit("phone module requires a number")
        phone_recon(args.target, args.case)
    elif args.module == "email":
        if not args.target: sys.exit("email module requires an address")
        email_recon(args.target, args.case)
    elif args.module == "domain":
        if not args.target: sys.exit("domain module requires a domain")
        domain_recon(args.target, args.case)
    elif args.module == "crypto":
        if not args.target: sys.exit("crypto module requires an address")
        crypto_recon(args.target, args.case)
    elif args.module == "social":
        if not args.target: sys.exit("social module requires a handle")
        social_recon(args.target, args.case)
    elif args.module == "ipinfo":
        if not args.target: sys.exit("ipinfo module requires an IP")
        ip_info(args.target, args.case)
    elif args.module == "combo":
        if not any([args.phone, args.email, args.domain, args.crypto, args.handle]):
            sys.exit("combo needs at least one of --phone/--email/--domain/--crypto/--handle")
        combo_recon(args.case, args.phone, args.email, args.domain, args.crypto, args.handle)
    elif args.module == "summary":
        build_summary(args.case)
    elif args.module == "report":
        build_report(args.case)

if __name__ == "__main__":
    main()
