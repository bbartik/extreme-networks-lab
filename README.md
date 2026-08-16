# extreme-platform-one-lab — retail RF/WLAN example config

Example Extreme Platform ONE / ExtremeCloud IQ tenant config for the same
fictional retail chain as [`juniper-mist-lab`](https://github.com/bbartik/juniper-mist-lab),
re-derived for Platform ONE rather than ported field-for-field — see
`HANDOFF-extreme-platform-one.md` for why that distinction matters and the
process this repo followed. Everything is prefixed `BB-` to stay
identifiable and safely deletable in a shared tenant.

## What's confirmed vs. assumed — read this first

Built in six passes: public-docs-only, a read-only live pass, an actual
deploy, a correction pass against the tenant's own real `v1` OpenAPI spec
(`.docs/api-1.json`, "ExtremeCloud IQ API" v25.11.1-3, gitignored — pulled
from the developer portal mid-session), then a final run of passes that
found a **second, older API generation** (`v0`, "classic XIQ") via
requests the user captured directly from their own browser's devtools
while using the real Platform ONE UI. That `v0` discovery closed every
gap the documented `v1` API never had an answer for: SSID creation,
attaching a Classification Rule to an SSID, AP device template creation,
and attaching an AP device template to a Network Policy via
classification rule (the last of these briefly looked like a genuine
vendor bug — a real captured UI save 404'd — before turning out to need
one undocumented field, `enableClassification: true`).

`push.py` has been run against a live tenant repeatedly and now completes
end-to-end (exit code 0): it creates VLAN/User/Radio profiles, AP device
templates, Site Groups, Classification Rules, and one Network Policy,
then fully creates/configures/classifies/attaches both the SSIDs and the
AP device templates to it. **74 real objects exist in this tenant because
of it**, and all 10 SSIDs plus all 5 AP templates carry their real
classification-rule assignment, confirmed live via fresh `GET`s, not just
trusting write responses.

**Confirmed working end-to-end** (created/updated/configured for real):
- VLAN Profiles, User Profiles, Radio Profiles (one per band), Site
  Groups, and a thin-shell Network Policy — see prior session notes
  preserved in each file's header for the specific gotchas found along
  the way (a required field that only errors on `null`, an enum whose
  values only appeared in a rejection message, a `PUT`-vs-`PATCH`
  inconsistency between object types, etc).
- **Classification Rules** (`/classification-rules`) — real, working,
  POST-able `v1` endpoint, keyed off **Site Group** rather than Cloud
  Config Group (switched at the user's direction, since Site Groups
  already exist and don't have the CCG dependency below).
  `classification_type: "CLASSIFICATION_TYPE_LOCATION"` +
  `classification_type_id: <real site group id>` — a pattern already in
  use by this tenant's own pre-existing rules (`AllOffices` references
  `CompuNet`'s own location id the same way). All 5 rules
  (`BB-Rule-DistributionCenter/CorporateOffice/Retail/RetailMall/PopUp`)
  are live.
- **Cloud Config Groups** (`/ccgs`) — real, working, POST-able `v1`
  endpoint, but a CCG cannot be created with an empty `device_ids` array
  (confirmed live via a 400) — at least one real device id is required.
  Since no `BB-` site has real hardware claimed, none of the four groups
  exist; `push.py` skips them cleanly. (No longer load-bearing for
  classification, now that rules key off Site Group instead — see above.)
- **SSID creation, for real.** There is no creation endpoint in the
  documented `v1` API (confirmed by searching all 519 spec paths, twice).
  It lives entirely on a separate, undocumented host:
  `POST https://cloudapi.extremecloudiq.com/xiq/v0/config/ssid/ssidprofiles/common?ownerId=<id>&ownerIds=<id>`
  — found from real captured browser traffic, then verified with a live
  create → read (via `v1`) → delete round-trip before being trusted.
  `create_ssid_v0()` in `push.py` builds this request (a rich, camelCase,
  `jsonType`-tagged object — a completely different shape from the `v1`
  API) with deliberately minimal/placeholder security and VLAN settings,
  then `configure_ssid()` (`v1`, already working) immediately overwrites
  both to the real desired values. Splitting it this way meant only the
  bare-minimum `v0` shape needed reverse-engineering, not a full
  per-security-mode variant.
- SSID configuration itself: `PUT /ssids/{id}/mode/{open,psk}` (fully
  implemented), VLAN via `POST /ssids/{id}/user-profile/:attach`, policy
  attachment via `POST /network-policies/{id}/ssids/:add` (bare array of
  ids — the `:add` action-verb suffix is why every earlier guess at a
  plain sub-resource `POST` 405'd). `PPSK` needs a `user_group_ids` array
  and `DOT1X` needs `enable_idm` or a real `radius_server_group_id` —
  both real fields referencing object types not explored this session;
  `push.py` creates those SSIDs but leaves them unconfigured and
  unattached with a clear message, rather than guess.
- **Attaching a Classification Rule to an SSID, for real** — the
  "Classification Rules" column visible on a Network Policy's Wireless
  Networks table in the UI. Also has no documented endpoint; found the
  same way as SSID creation, from a request the user captured in their
  own browser devtools while actually using the checkbox in the UI:
  `PUT https://cloudapi.extremecloudiq.com/xiq/v0/config/ssid/ssidprofiles/networkpolicy/{policyId}/summary`,
  body carrying the SSID's summary fields plus `classifiedEntries`, each
  wrapping the FULL nested classification-rule object (a bare id
  reference 400's, same pattern as SSID creation needing the full nested
  `defaultUserProfile`) — see `attach_classification_rules_v0()`. All 10
  SSIDs now have their matching rule(s) attached for real (Distribution
  Center/Corporate Office/Retail+RetailMall/PopUp), confirmed live in the
  actual UI.
- **AP device templates, for real.** `POST /config/device/templates` (`v0`
  host, plus an extra `vocoLevel=10` query param whose meaning is
  unconfirmed — present in the real captured request, kept as-is). Found
  from a request the user captured while creating one by hand and saved
  in full to `.docs/ap-template.json` (gitignored, ~1500 lines). A device
  template is per **AP model** (`productType`, e.g. `AP_5010` — every
  template here assumes that model, at the user's direction) and embeds a
  MUCH richer "radio profile" than this repo's `v1` `radio_profiles.yaml`
  targets — a different concept sharing a name, ~150 fields deep
  (`neighborhoodAnalysis`, `channelSelection`, `radioUsageOptimization`,
  etc.), appearing twice per band (byte-identical top-level field +
  nested copy inside `interfaceSettings.wirelessInterfaceSettings.entries[]`).
  "Band off" (needed for `AP-5010-CorporateOffice`/`RetailMall`) is
  `disableAllSsids: true` on that band's interface entry — confirmed from
  a real diff the user captured between an on/off pair
  (`.docs/ap-template-24off.json`), not a profile change. Real gotcha on
  update: `PUT` without the object's own `id` *also* present in the body
  (not just the URL) 500's with a useless generic error — fixed by
  including it. Real gotcha on idempotency: `GET
  /config/device/templates` hard-caps at 100 of this tenant's 370 total
  (almost all Extreme's own predefined-per-model templates), and no query
  param tried (offset/size/name/filter/search/q) changes that — existing-
  template lookup uses this repo's own `state/created_objects.json`
  instead of a fresh server list. All 5 templates
  (`AP-5010-DistributionCenter/CorporateOffice/Retail/RetailMall/PopUp`)
  are live.
- **AP templates attached to the Network Policy via classification rule,
  for real.** `POST /config/device/templateprofiles/networkpolicy/{policyId}`
  (`v0`) with `enableClassification: true` — a field absent from every
  early attempt, including a real capture of the actual UI's own save
  request, which came back as a genuine 404 with the UI showing the
  change anyway (a real optimistic-update bug on the vendor's part,
  briefly indistinguishable from "this API doesn't work at all" — see
  `device_templates.yaml` for the full story). `PUT` never worked at
  either the policy-scoped or item-level path even after the fix; `POST`
  does, and re-running is safe even though it allocates a new profile id
  each time — confirmed live the backend keeps exactly one per
  (policy, productType), the previous id is simply gone afterward. All 5
  templates now carry their real Site-Group-based classification rule,
  verified with a fresh `GET` (not just trusting the write response).

**Confirmed genuinely blocked**:
- **True `SITE`-type location creation.** `POST /locations` silently
  ignores the `type` field — sending `type: "SITE"` still creates a Site
  Group (proven by creating and reading back a disposable test object).
  `push.py` skips site creation (`SITE_TYPE_CREATE_CONFIRMED = False`).
  This gap wasn't revisited once `v0` access was found — the same
  "capture a real browser request" approach would very likely resolve it
  too; it just wasn't the priority this session.
- **Cloud Config Group creation without a real device** — see above.

**Design change**: collapsed from four+ Network Policies down to **one**,
`BB-NP-Wireless`, at the user's suggestion after re-reading Platform
ONE's own docs — a policy is meant to cover "multiple APs, switches, and
routers that share a common characteristic." Now that PPSK is confirmed
real and active in this tenant, `BB-Retail-POS` is one PPSK SSID instead
of N literal-PSK SSIDs across N policies (though PPSK itself still needs
`user_group_ids` to actually configure — see above).

One correction on top of that: `user_profile_assignment_rules` does
**not** reference Cloud Config Group (or Site Group) directly — the real
schema references a separate `user-profile-assignments` object (real and
creatable, scoped by location-folder ids or RADIUS attribute — a Site
Group's id would satisfy `folder_ids` directly), not built this session.
That object, attached to an SSID via `POST /ssids/{id}/user-profile-assignment/:attach`,
may be the more literal mechanism behind the "Classification Rules"
column visible on a Network Policy's Wireless Networks table in the real
UI — the standalone `/classification-rules` objects built this session
are real and live, but whether the UI reads from those specifically or
from `user-profile-assignments` (or both, under one label) wasn't
confirmed.

## Scenario

Same four site formats, two example sites each, as the Mist lab:

| Format | Sites | Distinguishing choice |
|---|---|---|
| Distribution Center | Dallas, Reno | 2.4GHz kept alive for legacy scanners, high power for open warehouse floors |
| Corporate Office | Austin HQ, Chicago | 2.4GHz off, lower power for AP-dense floors, dot1x staff SSID |
| Retail - standalone | Denver #0142, Columbus #0210 | Baseline RF, no neighboring-tenant contention |
| Retail - mall-colocated | Scottsdale #0087, King of Prussia #0311 | Same SSIDs as standalone, but a much lower power ceiling |
| Pop-up | NYC Holiday, Austin SXSW | Everything PSK, mesh-enabled AP template for uncabled spaces |

Full reasoning for each choice is in the `comment` fields inside the YAML files.

## Layout

```
config/
  locations.yaml            Site Groups (real, working) + Sites (creation blocked)
  vlan_profiles.yaml        /vlan-profiles + /user-profiles — confirmed working
  radio_profiles.yaml       /radio-profiles — confirmed working, one object per band
  cloud_config_groups.yaml  /ccgs — real, working; blocked until a real device exists to populate device_ids
  classification_rules.yaml /classification-rules — real, working; references a CCG by real id
  device_templates.yaml     AP templates (real, working, v0) + Switch templates (still speculative, no endpoint found)
  network_policies.yaml     ONE /network-policies shell + its SSIDs — both created and configured for real
scripts/
  p1_client.py           API wrapper for BOTH API generations (v1 REST + v0 classic), pagination, dynamic PUT/PATCH
  discover.py            confirmed-endpoint sanity check
  push.py                idempotent create/configure — run repeatedly against a live tenant, SSIDs included
  teardown.py            deletes exactly what push.py CREATED — never touches an SSID it only configured
state/
  created_objects.json   real object IDs from the live tenant — source of truth for deletion
.docs/
  api-1.json              the real v1 OpenAPI spec (gitignored — not this repo's to redistribute)
```

## Wired

Still genuinely unresolved: no equivalent of Mist's `switch_matching`/
`match_role` was found, and device templates themselves have no confirmed
endpoint at all in the `v1` API — the same "capture real browser traffic"
approach that solved SSIDs was never applied here. This repo's switch
templates (`BB-DT-Retail-Switch`, `BB-DT-{DistributionCenter,
CorporateOffice}-Switch-{Core,IDF}`) remain local-only YAML with no push
path.

## Deploying real hardware to a site

Same scope boundary as the Mist lab: even once a device is claimed,
there's no confirmed way to create a true Site for it to attach to, and
Cloud Config Groups can't be created without a real device id.
Confirmed-real endpoints exist for device assignment (`PUT
/devices/{id}/location`, `PUT /devices/{id}/policy`), write shape not
tested. Once Site creation is unblocked:

1. Power on the device with a live uplink so it can phone home.
2. Claim it into the tenant (mechanism not confirmed this session).
3. Assign it to a Site: `PUT /devices/{id}/location`.
4. Assign it the Network Policy: `PUT /devices/{id}/policy`.
5. Add its device id to the relevant group in `cloud_config_groups.yaml`
   and re-run `push.py` — that group (and its classification rule) can
   now actually be created.
6. Verify against the actual device, not just a follow-up GET — the
   single biggest lesson from the Mist session (HANDOFF Section 2.4): an
   API accepting a payload is not proof it did what you think it did.

## Adding a new SSID or store

New SSID: add an entry under `network_policies.yaml`'s `ssids:` list and
run `push.py` — it creates it via `v0`, configures it via `v1`, and
attaches it to `BB-NP-Wireless`, no manual UI step needed anymore for
`OPEN`/`PSK` modes.

New store: add one entry to `config/locations.yaml`'s `sites` list (see
the commented-out example at the bottom of that file). The site group and
everything else picks it up; the site itself won't create until
Site-type creation is unblocked (see above).

## Secrets

Real SSID passphrases live in `config/secrets.yaml`, gitignored and never
committed. Tracked YAML only ever holds a reference: `key_value: "!secret"`
in `network_policies.yaml`, resolved by `push.py` and keyed by SSID name.
`config/secrets.example.yaml` is the tracked template. There's no
per-site secret (`BB-Retail-POS` moved to PPSK).

## Getting your API access

Two things needed now, both in `.env` (see `.env.example`):
- `P1_API_TOKEN` — a static API key (shape `extr_sk_v1...`), works as a
  Bearer token against both API generations.
- `P1_OWNER_ID` — your specific admin account id, required for `v0` calls
  (not the same as `org_id`, which is always `0` in this tenant). No
  known way to discover it via API; watch any `v0` request in browser
  devtools (`?ownerId=...` query param) to find yours.

The corporate-network SSL error you may hit locally (`self-signed
certificate in certificate chain`) is a TLS-inspection proxy, not an API
problem — `pip install pip-system-certs` fixes it.

## Usage

```bash
pip install -r requirements.txt
python scripts/discover.py        # read-only sanity check
python scripts/push.py            # idempotent — safe to re-run any time
python scripts/teardown.py        # dry run, lists what would be deleted
python scripts/teardown.py --yes  # actually deletes it
```

`push.py` matches every object by `name` and updates in place rather than
duplicating. `state/created_objects.json` is saved in a `finally` block,
so a run that dies partway through still records everything it actually
created before the failure.

## Should this live in YAML instead of just clicking around in Platform ONE?

Same answer as the Mist repo, for the same reasons — plus one concrete
one: this session hit a long string of real, silent API gotchas across
two entire API generations (a required field with no hint until you send
`null`, an enum whose values only appeared in a rejection message, a
`type` field that's silently ignored, an action-verb-suffixed endpoint no
plain-noun guess would find, and finally a whole second undocumented API
host that only revealed itself through captured browser traffic). None of
that was guessable from docs alone, and most of it wouldn't have been
findable through the documented API's *own* reference material either —
it took the user's real UI session to close the final gap. Clicking
through a UI wizard would have hidden every one of these behind a green
checkmark instead of a script that made each failure isolatable to one
field, and a repo that now remembers exactly how the working request is
shaped instead of relying on someone doing it by hand again next time.
