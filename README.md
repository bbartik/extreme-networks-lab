# extreme-platform-one-lab

Config-as-code for a fictional retail chain's wireless network on Extreme
Platform ONE / ExtremeCloud IQ: RF profiles, AP device templates, SSIDs,
classification rules, and site structure, deployed via idempotent Python
scripts against the real API. Everything is prefixed `BB-` so it stays
identifiable and safely deletable in a shared tenant.

## Scenario

Four site formats, two example sites each:

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
  locations.yaml            Site Groups + Sites (each Site gets one Building + one Floor — see below)
  vlan_profiles.yaml        VLAN Profiles + User Profiles (the VLAN-assignment chain for an SSID)
  radio_profiles.yaml       Radio Profiles, one object per band
  cloud_config_groups.yaml  Device groups — populated once real hardware is claimed into a site
  classification_rules.yaml Rules that route SSIDs/AP templates to the right site group
  device_templates.yaml     AP device templates (per AP model) + switch templates (per model+stack size, one real so far)
  network_policies.yaml     One shared Network Policy + its SSIDs
scripts/
  p1_client.py              API client (see "Talking to Platform ONE" below)
  discover.py               Read-only sanity check — confirms the token works, lists key objects
  push.py                   Idempotent create/configure — safe to re-run any time
  teardown.py               Deletes exactly what push.py created (dry-run by default)
state/
  created_objects.json      Real object IDs from the live tenant — source of truth for deletion
.docs/
  (gitignored)              Reference material pulled from the tenant's own API/UI — see below
```

## Talking to Platform ONE

Two separate API generations are in play, and this repo uses both:

- **The documented REST API** (`https://api.extremecloudiq.com`, referred
  to in code as `v1`) — snake_case fields, covers VLAN/User/Radio
  profiles, Site Groups, Network Policies, Classification Rules, Cloud
  Config Groups, and SSID *configuration* (mode, PSK, VLAN assignment,
  policy attachment). A real OpenAPI spec for this generation, pulled
  from the developer portal, lives at `.docs/api-1.json` if present
  (gitignored — not this repo's to redistribute).
- **The classic API** (`https://cloudapi.extremecloudiq.com/xiq/v0`,
  referred to as `v0`) — an older, richer, camelCase/`jsonType`-tagged
  API that the web UI itself still uses for operations the documented
  API doesn't expose at all: creating a brand-new SSID, creating an AP
  device template, and attaching either one to a Network Policy via
  classification rule. `p1_client.py` wraps both hosts; the same bearer
  token authenticates against either.

Both are needed because SSIDs and AP device templates can only be
*created* through `v0` — the documented `v1` API can configure an
existing one but has no creation endpoint for either object type at all.
`push.py` uses `v0` for that one step and `v1` for everything else.

Within `v1` itself, locations aren't as uniform as they look: Site Groups
go through one generic, type-agnostic pair of paths (`POST /locations`,
`PUT /locations/{id}`), while Sites, Buildings, and Floors each have
their own dedicated, singular-named path (`POST /locations/site`, etc.) —
sending `type: "SITE"` to the generic endpoint silently creates a Site
Group instead of erroring, which is what made this easy to miss at
first.

## AP Device Templates

A device template is scoped to a specific **AP model** (`product_type`,
e.g. `AP_5010` — every template in this lab assumes that model). Each one
embeds its own radio configuration per band (2.4/5/6GHz) — a materially
richer object than the standalone Radio Profiles in `radio_profiles.yaml`
(those target the `v1` API and aren't referenced by device templates at
all; they're two different concepts that happen to share a name). Turning
a band off (used for the Corporate Office and Retail-Mall formats) is
done by disabling SSID broadcast on that band's radio interface within
the template, not by removing the band's configuration.

Building a template from scratch requires a full reference object as a
base (see `.docs/ap-template.json` if present, gitignored) — `push.py`
customizes a copy of it per format (power ceiling, which bands are on)
rather than constructing one from nothing.

## Switch Templates

Wired hardware is Switch Engine 5320-16P-4XE. Unlike AP templates,
Extreme needs a **separate template per stack size** — a stack's uplink
ports aren't uniformly free across every unit, since some get consumed by
the inter-unit stacking links themselves, and how many depends on a
unit's position in the stack. `device_templates.yaml`'s
`switch_templates:` models this: `SWE-5320-Retail-Stack1/2/3` (stores can
run 1-3 units), `SWE-5320-{Format}-Core` (an MC-LAG pair — two
independent standalone switches, not a 2-unit stack), and
`SWE-5320-{Format}-IDF-Stack1/2/3` (access closets, same variable sizing
as Retail). Pop-up stores don't get one — no wired infrastructure in an
uncabled space.

Two are real and pushed: `SWE-5320-Default` (no classification rule —
the policy-wide fallback for the whole product type, plain Access Port
on every port) and `SWE-5320-Retail-Stack1` (classification-rule-gated
to Retail/RetailMall, `port_plan:` assigns AP ports and the firewall
uplink the `trunk` role). Every other template in the list is still
planning data, skipped per-item until each one gets its own real
create/capture pass the same way this one did. One real, permanent
limitation: a trunk port can only be used as Extreme's own shared
predefined default, completely unmodified — it can't be customized to
tag specific VLANs or moved between templates, so trunk ports in this
lab carry every VLAN rather than a scoped list (still satisfies "carry
the wifi VLANs to the AP," just less precisely than originally intended).
See `ENGINEERING-NOTES.md` for the full story of how that limitation was
confirmed.

They attach to the same shared `BB-NP-Lab` policy as SSIDs and AP
templates, via the same Site-Group-based Classification Rules. One real
gap those rules can't close: they resolve to Site Group granularity, so
they can pick a default template for an entire DC/Corp site but can't
distinguish a Core switch from an IDF switch within it — Core has to be
assigned directly to its two device ids at claim time.

## Sites, Buildings, and Floors

A device can only be claimed into a Building or Floor — never a bare
Site. `push.py` creates one Building (`Main`) and one Floor (`1`) under
every Site for exactly that reason; both are overridable per site with
`building:`/`floor:` in `locations.yaml`. Site, Building, and Floor each
have their own typed API path (`/locations/site`, `/locations/building`,
`/locations/floor`) completely separate from the one Site Groups use —
see "Talking to Platform ONE" below.

## Network Policies & Classification Rules

All sites share **one** Network Policy (`BB-NP-Lab`) rather than one per
site format — a policy is meant to cover any group of devices that share
a characteristic, so a single shared policy plus per-format
Classification Rules is the more native shape than duplicating policies.
This holds for wired too: switch templates attach to the same
`BB-NP-Lab` policy as SSIDs and AP templates, not a separate wired
policy — renamed from `BB-NP-Wireless` once switch templates joined it,
so the name doesn't undersell what it actually covers. Each
Classification Rule matches a Site Group, and SSIDs, AP templates, and
switch templates all get tagged with the rule for their format — so the
one policy resolves to different behavior depending on which site group
a device sits in.

Three separate things have to all be true for a policy to actually cover
wired devices — easy to miss since each fails silently on its own:

1. A real switch device-template-profile attached underneath it
   (`push.py`'s `attach_switch_templates_v0`).
2. The policy object's own `type` field set to
   `NETWORK_ACCESS_AND_SWITCHING` rather than plain `WIRELESS_ACCESS` —
   the real UI's policy wizard has an explicit "Policy Type" checkbox
   pair (Wireless / Switching-Routing) that reads straight from this
   field.
3. The VLANs themselves attached to the policy's own Switching/Routing >
   VLAN Attribute table (`attach_vlan_attributes_v0`) — a genuinely
   separate step from either of the above, and from the VLAN Profile's
   own classification (`enable_classification`/`classified_entries`,
   which only makes a VLAN *classification-aware*, not attached to any
   particular policy's switching config).

`BB-Retail-POS` (the payment-terminal SSID) uses PPSK (Private PSK) so
every retail store can share one SSID definition with a distinct
passphrase per store, rather than needing a separate SSID per site.

## Known limitations

- **Cloud Config Groups** require at least one real (already-claimed)
  device to create — none exist in this lab since there's no real
  hardware. Not load-bearing for anything else here since Classification
  Rules key off Site Group instead.
- **Switch/wired templates**: only `SWE-5320-Default` and
  `SWE-5320-Retail-Stack1` are real and pushed (see "Switch Templates"
  above) — the rest of the `switch_templates` section is still
  local-only planning data with no push path yet.
- **`PPSK` and `DOT1X` SSID modes** need additional object types
  (`user_group_ids` for PPSK, a RADIUS server group or `enable_idm` for
  DOT1X) that aren't modeled yet — those SSIDs get created but left
  unconfigured, with a clear message instead of a guess.

## Deploying real hardware to a site

1. Power on the device with a live uplink so it can phone home.
2. Claim it into the tenant.
3. Assign it to a Building or Floor (not the Site itself — that's not a
   valid claim target): `PUT /devices/{id}/location`.
4. Assign it the Network Policy: `PUT /devices/{id}/policy`.
5. Add its device id to the relevant group in `cloud_config_groups.yaml`
   and re-run `push.py` — that group (and its classification rule) can
   now actually be created.
6. Verify against the actual device, not just a follow-up API read — an
   API accepting a payload isn't proof it applied the way you expect.

## Adding a new SSID or store

**New SSID**: add an entry under `network_policies.yaml`'s `ssids:` list
and run `push.py` — it creates it, configures it, and attaches it to
`BB-NP-Lab` in one pass for `OPEN`/`PSK` modes.

**New store**: add one entry to `config/locations.yaml`'s `sites` list
(see the commented-out example at the bottom of that file) and run
`push.py` — it creates the Site plus its Building and Floor in one pass.

## Secrets

Real SSID passphrases live in `config/secrets.yaml`, gitignored and never
committed. Tracked YAML only ever holds a reference: `key_value: "!secret"`
in `network_policies.yaml`, resolved by `push.py` and keyed by SSID name.
`config/secrets.example.yaml` is the tracked template.

## Getting your API access

Two things needed, both in `.env` (see `.env.example`):

- `P1_API_TOKEN` — a static API key, works as a Bearer token against both
  API generations.
- `P1_OWNER_ID` — your specific admin account id (not the same as
  `org_id`). No way to discover it via API; find it by watching any `v0`
  request in your browser's devtools (`?ownerId=...` query param).

If you're behind a corporate TLS-inspection proxy, you may see a
`self-signed certificate in certificate chain` error locally — that's not
an API problem, `pip install pip-system-certs` fixes it by making Python
trust the Windows certificate store.

## Usage

```bash
pip install -r requirements.txt
python scripts/discover.py        # read-only sanity check
python scripts/push.py            # idempotent — safe to re-run any time
python scripts/teardown.py        # dry run, lists what would be deleted
python scripts/teardown.py --yes  # actually deletes it
```

`push.py` matches every object by `name` and updates in place rather than
duplicating. `state/created_objects.json` records every object it's
responsible for, so a run that fails partway through still leaves an
accurate record of what exists.

## Why config-as-code for this

Individually clicking through the UI doesn't leave behind the *why* next
to each RF/auth choice, doesn't give you a diff before a change touches a
shared tenant, and doesn't give you a clean, repeatable teardown when this
is a lab meant to be rebuilt more than once. It also turned out to matter
more than usual here: several real API/UI quirks (fields that are
silently required with no validation hint, endpoints that exist on one
API generation but not another, a UI save that can 404 while still
showing the change as if it worked) only became visible by scripting
against the real API and checking results with a follow-up read — not by
clicking through a wizard that hides all of that behind a green checkmark.
