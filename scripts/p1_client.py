"""Thin wrapper around the Extreme Platform ONE / ExtremeCloud IQ API: auth,
base URL, and a name-based get-or-create/update helper that makes push.py
idempotent.

Corrected against a real tenant on 2026-08-15 (read-only — every fact below
came from a live GET, no POST/PUT/DELETE has been run this session):

- List endpoints (/radio-profiles, /ssids, /network-policies,
  /vlan-profiles, /user-profiles) return a paginated envelope:
  {page, count, total_pages, total_count, data: [...]}. One tenant's
  /radio-profiles alone already spans 2 pages — get_all() below follows
  ?page=N until total_pages is exhausted, otherwise upsert_by_name would
  silently miss objects on later pages and duplicate them.
- /locations/sites and /locations/buildings (PLURAL) reject GET outright
  (400 "Request method 'GET' not supported"). CORRECTED 2026-08-16: this
  is not "no list endpoint exists" — the SINGULAR typed paths
  (/locations/site, /locations/building, /locations/floor) are real GET
  list endpoints (paginated ?page=N&limit=N, see
  get_all_typed_location()), confirmed from the user's own already-working
  reference scripts. Site Groups still only have /locations/tree to read
  from (no /locations/site-group singular path found/tried yet) —
  list_locations_by_type() stays the read path for that one type.
- Still unverified: any POST/PUT/DELETE body shape for any object type.
  Before trusting push.py at scale, do the create -> GET -> delete
  round-trip per type yourself (HANDOFF Section 2.2).

Auth: this tenant's token has the shape of a real static Platform ONE API
key (`extr_sk_v1...`), confirmed working as a Bearer token — the
static-token assumption in the first draft of this file was correct for
this tenant. (ExtremeCloud IQ's classic API also documents a separate
POST /login username+password flow returning a 24h JWT; not needed here
since a static key already works.)

There are TWO real, separate APIs in play, confirmed live 2026-08-16 via
captured browser traffic: the documented "v1" REST API (base_url above,
snake_case fields, thin objects — everything in this file until now) and
an older "v0 classic XIQ" API (v0_base_url, camelCase fields, rich
jsonType-tagged objects) that the web UI itself still uses for operations
v1 never got, most importantly SSID creation (see push.py's
create_ssid_v0). Same bearer token authenticates against both hosts. v0
calls need an extra `ownerId` (a specific admin account id, NOT org_id —
see .env.example) that v1 calls don't.
"""
import os
import sys
import requests
from dotenv import load_dotenv

_ENV_PATH = os.path.join(os.path.dirname(__file__), "..", ".env")
load_dotenv(_ENV_PATH)


class P1Client:
    def __init__(self):
        self.token = os.environ.get("P1_API_TOKEN")
        self.base_url = os.environ.get("P1_BASE_URL", "https://api.extremecloudiq.com").rstrip("/")
        self.v0_base_url = os.environ.get("P1_V0_BASE_URL", "https://cloudapi.extremecloudiq.com/xiq/v0").rstrip("/")
        self.owner_id = os.environ.get("P1_OWNER_ID")
        if not self.token:
            sys.exit("P1_API_TOKEN must be set in .env")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        })

    def _url(self, path):
        return f"{self.base_url}{path}"

    def v0_get(self, path):
        """GET against the v0 classic API host, with the owner-id query
        params. Confirmed live: list endpoints return {"data": [...]}, no
        pagination envelope seen yet (unlike v1) — returned as-is."""
        if not self.owner_id:
            sys.exit("P1_OWNER_ID must be set in .env for v0 API calls (see .env.example)")
        url = f"{self.v0_base_url}{path}?ownerId={self.owner_id}&ownerIds={self.owner_id}"
        r = self.session.get(url, timeout=20)
        r.raise_for_status()
        return r.json()

    def v0_put(self, path, body):
        """PUT against the v0 classic API host, with the owner-id query
        params."""
        if not self.owner_id:
            sys.exit("P1_OWNER_ID must be set in .env for v0 API calls (see .env.example)")
        url = f"{self.v0_base_url}{path}?ownerId={self.owner_id}&ownerIds={self.owner_id}"
        r = self.session.put(url, json=body, timeout=20)
        if not r.ok:
            sys.exit(f"PUT (v0) {path} failed [{r.status_code}]: {r.text}")
        return r.json() if r.text else {}

    def v0_post(self, path, body, extra_params=None):
        """POST against the v0 classic API host, with the owner-id query
        params it needs (confirmed live 2026-08-16, real request captured
        from the web UI's own network traffic). Some v0 endpoints need
        extra query params beyond ownerId/ownerIds — e.g. device template
        create needs `vocoLevel=10`, real value captured the same way;
        meaning unknown, present in the real request so kept as-is."""
        if not self.owner_id:
            sys.exit("P1_OWNER_ID must be set in .env for v0 API calls (see .env.example)")
        params = f"ownerId={self.owner_id}&ownerIds={self.owner_id}"
        if extra_params:
            params += "&" + "&".join(f"{k}={v}" for k, v in extra_params.items())
        url = f"{self.v0_base_url}{path}?{params}"
        r = self.session.post(url, json=body, timeout=20)
        if not r.ok:
            sys.exit(f"POST (v0) {path} failed [{r.status_code}]: {r.text}")
        return r.json()

    def v0_delete(self, path):
        """DELETE against the v0 classic API host — confirmed live
        2026-08-16 (used to clean up the disposable BB-TEST-CreateProbe2
        object created while verifying create_ssid_v0 worked)."""
        r = self.session.delete(f"{self.v0_base_url}{path}", timeout=20)
        if r.status_code not in (200, 204, 404):
            sys.exit(f"DELETE (v0) {path} failed [{r.status_code}]: {r.text}")

    def get(self, path):
        r = self.session.get(self._url(path), timeout=20)
        r.raise_for_status()
        return r.json()

    def get_all(self, path):
        """GET a paginated list endpoint and return every item across all
        pages, unwrapped to a plain list. Confirmed envelope shape:
        {page, count, total_pages, total_count, data: [...]}."""
        first = self.get(path)
        if not isinstance(first, dict) or "data" not in first:
            return first if isinstance(first, list) else [first]
        items = list(first["data"])
        total_pages = first.get("total_pages", 1)
        sep = "&" if "?" in path else "?"
        for page in range(2, total_pages + 1):
            page_resp = self.get(f"{path}{sep}page={page}")
            items.extend(page_resp.get("data", []))
        return items

    def post(self, path, body):
        r = self.session.post(self._url(path), json=body, timeout=20)
        if not r.ok:
            sys.exit(f"POST {path} failed [{r.status_code}]: {r.text}")
        return r.json() if r.text else {}

    def put(self, path, body):
        r = self.session.put(self._url(path), json=body, timeout=20)
        if not r.ok:
            sys.exit(f"PUT {path} failed [{r.status_code}]: {r.text}")
        return r.json() if r.text else {}

    def update(self, path, body):
        """Update an item, choosing PUT or PATCH based on what the server
        actually allows. Confirmed live 2026-08-15: item-level update verb
        is NOT consistent across object types — /vlan-profiles/{id} only
        allows PATCH, while /network-policies/{id}, /user-profiles/{id},
        and /radio-profiles/{id} all allow PUT (found via a plain 400
        "Request method 'PUT' not supported" on vlan-profiles, then
        confirmed generally by checking each item endpoint's OPTIONS Allow
        header). Rather than hardcode the one known exception, this checks
        Allow every time — one extra cheap round-trip per update, worth it
        given how it's already proven to actually vary per type.
        """
        allow = self.session.options(self._url(path), timeout=20).headers.get("Allow", "")
        methods = {m.strip() for m in allow.split(",")}
        verb = "PATCH" if "PUT" not in methods and "PATCH" in methods else "PUT"
        r = self.session.request(verb, self._url(path), json=body, timeout=20)
        if not r.ok:
            sys.exit(f"{verb} {path} failed [{r.status_code}]: {r.text}")
        return r.json() if r.text else {}

    def delete(self, path):
        r = self.session.delete(self._url(path), timeout=20)
        if r.status_code not in (200, 204, 404):
            sys.exit(f"DELETE {path} failed [{r.status_code}]: {r.text}")

    def upsert_by_name(self, list_path, name, body, name_field="name"):
        """Create-or-update an object matched by its name field within a
        paginated collection. Returns (id, action) where action is
        'created' or 'updated'."""
        existing = self.get_all(list_path)
        match = next((o for o in existing if o.get(name_field) == name), None)
        if match:
            self.update(f"{list_path}/{match['id']}", body)
            return match["id"], "updated"
        created = self.post(list_path, body)
        return created["id"], "created"

    def get_all_typed_location(self, node_type, page_size=100):
        """GET the typed, singular location list endpoint — /locations/site,
        /locations/building, /locations/floor — paginated via ?page=N&limit=
        page_size (NOT the {page, total_pages, data} envelope the other v1
        list endpoints use; this one is a bare list, or missing entirely
        once a page comes back empty).

        Confirmed real 2026-08-16 from two already-working reference
        scripts the user supplied (.docs/xiq_sites.py,
        .docs/xiq_add_buildings_and_floors.py), dated Oct 2025 — real
        production automation predating this lab. This directly overturns
        this module's earlier "no GET list endpoint exists for these
        types" note: that belief came from testing the PLURAL path
        (/locations/sites), which does reject GET with a 400. The
        singular, typed path is a different, real route.
        """
        path = f"/locations/{node_type}"
        page = 1
        items = []
        while True:
            resp = self.get(f"{path}?page={page}&limit={page_size}")
            page_items = resp if isinstance(resp, list) else resp.get("data", [])
            if not page_items:
                break
            items.extend(page_items)
            if len(page_items) < page_size:
                break
            page += 1
        return items

    def location_tree(self):
        return self.get("/locations/tree")

    def list_locations_by_type(self, node_type, tree=None):
        """Walk /locations/tree and return every node of a given `type`
        ("Site_Group", "SITE", "BUILDING", "FLOOR" — confirmed live values).
        Needed because /locations/sites and /locations/buildings reject GET
        (see module docstring) — this is the only confirmed way to read
        existing locations back."""
        tree = tree if tree is not None else self.location_tree()
        roots = tree if isinstance(tree, list) else [tree]
        found = []

        def walk(node):
            if node.get("type") == node_type:
                found.append(node)
            for child in node.get("children", []):
                walk(child)

        for root in roots:
            walk(root)
        return found
