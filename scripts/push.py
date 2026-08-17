"""Idempotent push of config/*.yaml into the Platform ONE / ExtremeCloud IQ
tenant referenced by .env.

This has actually been run against a real tenant (2026-08-15/16, several
iterations) — real objects exist because of it: VLAN profiles, User
profiles, Radio profiles, Site Groups, one Network Policy, Cloud Config
Groups, and Classification Rules. Every real 400/404/silent-no-op hit
along the way is documented in the relevant config/*.yaml header.

SSID handling went through two real corrections. First (2026-08-16,
reading .docs/api-1.json, the tenant's own v1 OpenAPI spec): no SSID
creation endpoint exists in that API at all (confirmed by searching all
519 paths, twice — by URL text and by schema reference) — only mode/PSK/
VLAN/policy-attachment operations on an id that already exists. Second,
later the same day: SSID creation genuinely IS possible, just not through
that API — it lives on an entirely separate "v0 classic XIQ" host
(cloudapi.extremecloudiq.com/xiq/v0), found from a request the user
captured in their own browser devtools while using the real Platform ONE
UI, then verified with a live create -> GET (v1) -> delete round-trip.
See create_ssid_v0() for the full story. Site creation is separately
still confirmed BLOCKED (SITE_TYPE_CREATE_CONFIRMED below) for an
unrelated reason (the `type` field is silently ignored on location
create) — that gap wasn't revisited once v0 access was found, since it's
a different host/endpoint entirely; the same "capture a real browser
request" approach would likely resolve it too.

Order: vlan profiles -> user profiles (VLAN assignment for an SSID runs
through this chain, not a field on the SSID itself — see
vlan_profiles.yaml) -> radio profiles (one object per band) -> cloud
config groups -> classification rules (reference a CCG by its real id —
see classification_rules.yaml) -> site groups + sites (sites currently
skipped, see below) -> the one network policy -> its SSIDs (created via
v0 if missing, then fully configured via v1, then attached to the
policy).

Re-running is meant to be safe: objects are matched by `name` and updated
in place rather than duplicated. Every created/updated id is recorded in
state/created_objects.json — saved in a `finally` block so a run that
dies partway through still records everything it actually created before
the failure.
"""
import copy
import json
import os
import sys
from datetime import datetime, timezone

import yaml

from p1_client import P1Client

CONFIG_DIR = os.path.join(os.path.dirname(__file__), "..", "config")
DOCS_DIR = os.path.join(os.path.dirname(__file__), "..", ".docs")
STATE_PATH = os.path.join(os.path.dirname(__file__), "..", "state", "created_objects.json")
SECRETS_PATH = os.path.join(CONFIG_DIR, "secrets.yaml")

# RESOLVED 2026-08-16. POST /locations silently ignores the `type` field
# entirely (confirmed live 2026-08-15: sending type: "SITE", and later
# type: "BUILDING", both came back "type": "Site Group") — that's a real,
# separate bug in the generic /locations endpoint, but it turned out not
# to be the whole story: SITE/BUILDING/FLOOR were never reachable through
# the generic endpoint at all. They live behind their OWN typed collection
# paths — POST/GET /locations/site, /locations/building, /locations/floor
# (singular) — confirmed real from two already-working reference scripts
# the user supplied (.docs/xiq_sites.py, .docs/xiq_add_buildings_and_floors.py,
# dated Oct 2025 — real production automation predating this lab, not a
# fresh capture). Every "site" this repo created before this point is
# actually a nested Site_Group folder under the generic endpoint, not a
# true SITE node — those are harmless leftovers, not something later runs
# need to clean up specially (teardown.py deletes them the same way either
# way). See build_site_body()/build_building_body()/build_floor_body() and
# upsert_typed_location() below for the real schemas.
SITE_TYPE_CREATE_CONFIRMED = True

# Keys that exist in the YAML for documentation/cross-referencing/local
# resolution but aren't real Platform ONE API fields — stripped before
# anything is sent.
NON_API_KEYS = {"comment", "site_group", "radio_profile", "device_template_ap",
                 "network_policy", "vars", "name_prefix", "vlan_profile",
                 "user_profile", "cloud_config_group", "classification_rules",
                 "building", "floor"}


def load(name):
    with open(os.path.join(CONFIG_DIR, f"{name}.yaml"), encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_secrets():
    if not os.path.exists(SECRETS_PATH):
        sys.exit(
            f"Missing {SECRETS_PATH}. Copy config/secrets.example.yaml to "
            f"config/secrets.yaml and fill in real values."
        )
    with open(SECRETS_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def clean(obj):
    obj = copy.deepcopy(obj)
    for k in NON_API_KEYS:
        obj.pop(k, None)
    return obj


def resolve_psk_secret(key_value, ssid_name, secrets):
    if key_value != "!secret":
        return key_value
    psks = secrets.get("ssid_psks", {})
    if ssid_name not in psks:
        sys.exit(f"No ssid_psks entry for {ssid_name} in {SECRETS_PATH}")
    return psks[ssid_name]


def create_ssid_v0(client, ssid_cfg):
    """Create a bare SSID via the v0 "classic XIQ" API — confirmed real
    and working 2026-08-16 from a request captured in the user's own
    browser devtools while using the actual Platform ONE UI, then verified
    by a live create -> GET (via v1) -> delete round-trip
    (BB-TEST-CreateProbe2). No creation endpoint exists in the newer v1
    API at all (confirmed by searching its full spec both by URL text and
    schema reference) — this v0 host is genuinely the only way.

    Deliberately minimal: accessSecurity is created as a PSK placeholder
    and defaultUserProfile as the tenant's real default (id 36000)
    regardless of what the YAML actually wants — configure_ssid() (v1,
    already confirmed working) immediately overwrites both to the real
    values right after. Splitting it this way means only ONE object shape
    needed guessing (this minimal create body) instead of reverse-
    engineering the v0 shape for every security mode.

    Most fields below are boilerplate copied verbatim from that real
    captured request — not independently tuned, since the create call
    doesn't validate them meaningfully as long as *something* well-formed
    is present (confirmed: changing the trafficFilter name was the only
    thing that mattered when the first attempt 400'd on a name collision).
    """
    name = ssid_cfg["name"]
    owner_id = int(client.owner_id)
    body = {
        "ownerId": owner_id, "jsonType": "ssid-profile", "name": name, "ssid": name,
        "enableMacAuthentication": False, "authenticationProtocol": "PAP", "description": "",
        "enableSchedule": False, "enableClientMonitor": True, "enableCwp": False,
        "enableAdvancedGuestAccess": False,
        "trafficFilter": {
            "jsonType": "traffic-filter", "predefined": False,
            "name": f"BB-TF-{name}-{owner_id}", "description": "", "enableSsh": True,
            "enableTelnet": False, "enablePing": True, "enableSnmp": False,
            "enableInterStationTraffic": True, "ownerId": owner_id,
        },
        "enableMacFilter": False, "macFilters": [], "macFilterDefaultAction": "PERMIT",
        "enableHide": bool(ssid_cfg.get("hidden", False)),
        "advancedSettings": {
            "predefined": False, "userProfileApplicationSequence": "MAC_SSID_CWP",
            "enableIgnoreBroadcastProbeRequest": False, "enableVoiceEnterprise": False,
            "enable802Dot11k": False, "enable802Dot11v": False, "enable802Dot11r": False,
            "enableWmm": True, "enableWmmVideo": False, "enableWmmVoice": False,
            "enableUnscheduledAutoPowerSaveDelivery": False, "multicastToUnicastConversion": "AUTO",
            "channelUtilizationThreshold": 60, "membershipCountThreshold": 10, "maxClientLimit": 100,
            "eapTimeout": 30, "rtsThreshold": 2346, "fragmentThreshold": 2346, "dtimSetting": 1,
            "inactiveClientAgeout": 5, "eapRetries": 3, "roamingCacheUpdateInterval": 60,
            "roamingCacheAgeout": 60, "localCacheTimeout": 86400,
            "enableNonEssentialBroadcastFiltering": True, "enableMulticastDrop": False,
            "enableExcludeDhcpv4": False, "enableExcludeDhcpv6": False, "enableExcludeArp": False,
            "enableExcludeIgmpQuery": False, "enableExcludeIpv6Discovery": False,
            "enableExcludeMdns": False, "ownerId": owner_id, "enableMLO": False,
        },
        "radioRateSettings": {
            "predefined": False, "enableCustomize11aRateSetting": True,
            "enableCustomize11bgRateSetting": True, "enableCustomize11nRateSetting": True,
            "enableCustomize11acRateSetting": True, "enableCustomize11axRateSetting": True,
            "maxSpatialStreams": 4, "oneStreamMcsIndex": 9, "twoStreamsMcsIndex": 9,
            "threeStreamsMcsIndex": 9, "fourStreamsMcsIndex": 9, "maxSpatialStreams11ax": 4,
            "oneStreamMcsIndex11ax": 11, "twoStreamsMcsIndex11ax": 11,
            "threeStreamsMcsIndex11ax": 11, "fourStreamsMcsIndex11ax": 11,
            "disable11nHighThroughputCapabilities": False,
            "_11aRateSettings": ["BASIC", "OPTIONAL", "BASIC", "OPTIONAL", "BASIC", "OPTIONAL", "OPTIONAL", "OPTIONAL"],
            "_11bgRateSettings": ["NA", "NA", "NA", "BASIC", "OPTIONAL", "OPTIONAL", "OPTIONAL", "OPTIONAL", "OPTIONAL", "OPTIONAL", "OPTIONAL", "OPTIONAL"],
            "_11nRateSettings": ["OPTIONAL"] * 32,
            "ownerId": owner_id,
        },
        "stationMacDos": None, "ssidMacDos": None, "ssidIpDos": None,
        "ssidMacDosId": 11000, "stationMacDosId": 11001, "ssidIpDosId": 9000,
        "accessSecurity": {
            "ownerId": owner_id, "keyManagement": "WPA2_PSK", "pweMethod": "BOTH_HNP_H2E",
            "encryptionMethod": "CCMP", "jsonType": "psk", "keyType": "ASCII",
            "keyValue": "placeholder-replaced-next", "enableAkm": False, "transitionMode": False,
            "antiLoggingThreshold": "5", "saeGroup": "ALL",
        },
        "pcgFilters": {
            "enablePcgBroadcastFiltering": False, "enablePcgMulticastFiltering": False,
            "enablePcgMulticastFilteringMdns": False, "enablePcgMulticastFilteringSsdp": False,
            "ownerId": owner_id,
        },
        "enablePpskGroup": False, "pcgType": "NONE", "hotspotProfileStatus": "DISABLED",
        "enableRadiusAttributeUserProfileAssignment": False, "enableUserProfileAssignment": False,
        "attributeType": "STANDARD", "attributeKey": "11", "vendorId": "",
        "userProfileAssignmentRules": [],
        # A bare {"id": 36000} reference was rejected with a generic
        # "input is not valid" 400 — the create call needs the FULL
        # nested user-profile object, not just an id, confirmed by what
        # actually worked in the captured/tested request. configure_ssid()
        # (v1) immediately overwrites this to the real desired profile
        # right after creation, so this only needs to be structurally
        # valid, not semantically correct.
        "defaultUserProfile": {
            "id": 36000, "createdAt": 1423106508322, "updatedAt": 1423106508322,
            "ownerId": 0, "orgId": 0, "jsonType": "user-profile", "name": "default-profile",
            "description": "Default user profile", "predefined": True,
            "vlan": {
                "jsonType": "vlan-profile", "id": 40000, "createdAt": 1423106507502,
                "updatedAt": 1423106507502, "ownerId": 0, "orgId": 0, "name": "1",
                "description": "Default VLAN", "predefined": True, "classifiedEntries": [],
                "defVlanId": 1,
            },
            "isConnToVlanGroup": False, "enableFirewall": False, "enableTrafficTunneling": False,
            "enableSchedule": False, "enableClientSla": False, "enableQos": True,
            "enableUserDataTimeLimit": False, "attributeNumber": 0, "enableBypassAppleCna": False,
            "enableUrlFilter": False, "extremeIotDefined": False,
        },
        "radioBand": "DUAL", "schedules": [],
        "advancedAccessSecurity": {
            "predefined": False, "gtkRekeyPeriod": None, "gtkTimeout": 4000, "gtkRetries": 3,
            "ptkRekeyPeriod": None, "ptkTimeout": 4000, "ptkRetries": 3, "gmkRekeyPeriod": None,
            "replayWindow": 0, "enableNonStrict": False, "reauthInterval": None,
            "enablePreauthentication": False, "enableProactivePmkIdResponse": False,
            "enableLocalTkipCountermeasure": True, "enableRemoteTkipCountermeasure": True,
            "useOf802Dot11w": "MANDATORY", "enableGmkRekeyPeriod": False, "enableGtkRekeyPeriod": False,
            "enablePtkRekeyPeriod": False, "enableReauthInterval": False, "ownerId": owner_id,
            "enable802Dot11w": True, "enableBroadcastOrMulticastIntegrityProtocol": True,
            "enableBeaconProtection": False,
        },
        "userGroupIds": [], "enableIdm": False, "radiusClientProfile": None,
        "enableUztnaProxy": False, "enableUztnaDirect": False,
    }
    created = client.v0_post("/config/ssid/ssidprofiles/common", body)
    return created["data"]["id"]


def configure_ssid(client, sid, ssid_cfg, user_profile_ids, secrets, radius_server_ids=None):
    """Configure an EXISTING SSID (by real id) using the confirmed-real
    mode-setting endpoints found in the real OpenAPI spec (.docs/api-1.json,
    2026-08-16). Everything after bare creation — mode, PSK, VLAN (user
    profile), policy attachment — is real and scriptable via the v1 API.

    Returns True if fully configured (safe to attach to the policy), False
    if this SSID's mode needs an object type not explored this session
    (PPSK needs user_group_ids, a real "User Group" object — see
    network_policies.yaml header) — skipped with a clear message rather
    than guessed at.
    """
    sec = ssid_cfg["access_security"]
    sec_type = sec["security_type"]

    if sec_type == "OPEN":
        client.put(f"/ssids/{sid}/mode/open", None)
    elif sec_type == "PSK":
        body = {
            "key_management": sec["key_management"],
            "encryption_method": sec.get("encryption_method", "CCMP"),
            "key_type": sec.get("key_type", "ASCII"),
            "key_value": resolve_psk_secret(sec["key_value"], ssid_cfg["name"], secrets),
        }
        if sec["key_management"] == "WPA3_PSK":
            body["sae_group"] = sec.get("sae_group", "ALL")
        client.put(f"/ssids/{sid}/mode/psk", body)
    elif sec_type == "PPSK":
        print(f"    skipped mode config — PPSK needs user_group_ids (a User Group object, not explored this session)")
        return False
    elif sec_type == "TYPE_802DOT1X":
        # CONFIRMED REAL 2026-08-16, from .docs/api-1.json's
        # XiqSetSsidModeDot1xRequest, corrected twice by real errors:
        # - `enable_uztna` isn't marked required in the OpenAPI schema
        #   but the real server 400's with a null pointer exception
        #   (`XiqSetSsidModeDot1xRequest.getEnableUztna()` is null)
        #   without it.
        # - `enable_idm: false` + `enable_uztna: false` together 400's
        #   "Either IDM or UZTNA should be enabled" — the field's own
        #   description ("use ExtremeCloud IQ Authentication Service or
        #   not") reads like enable_idm:false should mean "use my own
        #   RADIUS server instead", but the real validation requires ONE
        #   of the two flags true regardless of whether
        #   radius_server_group_id is also provided. Since UZTNA
        #   (ExtremeCloud Universal ZTNA) is an unrelated real feature we
        #   don't want, enable_idm: true is the one that actually lets a
        #   real radius_server_group_id take effect alongside it.
        dot1x = ssid_cfg["dot1x"]
        body = {
            "enable_idm": True,
            "enable_uztna": False,
            "key_management": dot1x["key_management"],
            "encryption_method": dot1x.get("encryption_method", "CCMP"),
            "radius_server_group_id": radius_server_ids[dot1x["radius_server"]],
        }
        client.put(f"/ssids/{sid}/mode/dot1x", body)
    else:
        print(f"    skipped mode config — unhandled security_type {sec_type!r}")
        return False

    if ssid_cfg.get("user_profile"):
        up_id = user_profile_ids[ssid_cfg["user_profile"]]
        client.post(f"/ssids/{sid}/user-profile/:attach", up_id)
    return True


def _iso_to_epoch_ms(iso):
    return int(datetime.strptime(iso, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp() * 1000)


def _fetch_class_assignment_v0(client, rule_id):
    """Build the full nested "classAsgn" object shape the v0 API requires
    (a bare id reference was rejected with a generic "input is not valid",
    the exact same pattern SSID creation hit before switching to the full
    nested defaultUserProfile). Reads the rule back from the confirmed-real
    v1 /classification-rules/{id} endpoint and translates field names to
    what v0 calls them (classification_type -> classType stripped of its
    "CLASSIFICATION_TYPE_" prefix, classification_id -> folderId for
    LOCATION rules) — confirmed correct 2026-08-16 by successfully
    attaching BB-Rule-DistributionCenter to BB-DC-Ops this way.
    """
    rule = client.get(f"/classification-rules/{rule_id}")
    owner_id = int(client.owner_id)
    classifications = []
    for c in rule["classifications"]:
        classifications.append({
            "jsonType": "location-classification",
            "id": c["id"],
            "createdAt": _iso_to_epoch_ms(c["create_time"]),
            "updatedAt": _iso_to_epoch_ms(c["update_time"]),
            "ownerId": owner_id,
            "orgId": 0,
            "predefined": False,
            "classType": c["classification_type"],
            "match": c["match"],
            "folderId": c["classification_id"],
            "value": c["value"],
        })
    return {
        "id": rule["id"],
        "createdAt": _iso_to_epoch_ms(rule["create_time"]),
        "updatedAt": _iso_to_epoch_ms(rule["update_time"]),
        "ownerId": owner_id,
        "orgId": 0,
        "jsonType": "classification-assignment",
        "name": rule["name"],
        "description": rule.get("description", ""),
        "predefined": False,
        "classifications": classifications,
    }


def _build_vlan_obj_v0(client, vlan_profile_id):
    """Full v0-shaped "vlanObj" for a VLAN Attributes entry — CONFIRMED
    REAL 2026-08-16 from a request the user captured
    (.docs/vlan-add.json) after adding a VLAN to a policy's
    Switching/Routing > VLAN Attribute table in the real UI. Rather than
    hand-build this (the way _fetch_class_assignment_v0 does for a bare
    classification rule), this reads the VLAN profile straight back from
    the confirmed-real v1 /vlan-profiles/{id} endpoint — which, after the
    5c classification step above, already carries real
    classified_entries — and translates field names to what v0 calls
    them (same classType/folderId/match/value translation
    _fetch_class_assignment_v0 already does, just inlined here since the
    nesting differs: classifiedEntries live under vlanObj, not as a
    sibling).
    """
    owner_id = int(client.owner_id)
    v1 = client.get(f"/vlan-profiles/{vlan_profile_id}")
    entries = []
    for e in v1.get("classified_entries", []):
        rule = e["classification_rule"]
        classifications = [{
            "jsonType": "location-classification",
            "id": c["id"],
            "createdAt": _iso_to_epoch_ms(c["create_time"]),
            "updatedAt": _iso_to_epoch_ms(c["update_time"]),
            "ownerId": owner_id,
            "orgId": 0,
            "predefined": False,
            "classType": c["classification_type"],
            "match": c["match"],
            "folderId": c["classification_id"],
            "value": c["value"],
        } for c in rule["classifications"]]
        entries.append({
            "id": e["id"],
            "createdAt": _iso_to_epoch_ms(e["create_time"]),
            "updatedAt": _iso_to_epoch_ms(e["update_time"]),
            "ownerId": owner_id,
            "orgId": 0,
            "predefined": False,
            "classAsgn": {
                "jsonType": "classification-assignment",
                "id": rule["id"],
                "createdAt": _iso_to_epoch_ms(rule["create_time"]),
                "updatedAt": _iso_to_epoch_ms(rule["update_time"]),
                "ownerId": owner_id,
                "orgId": 0,
                "name": rule["name"],
                "description": rule.get("description", ""),
                "predefined": False,
                "classifications": classifications,
            },
            "vlanId": e["vlan_id"],
        })
    return {
        "id": v1["id"],
        "createdAt": _iso_to_epoch_ms(v1["create_time"]),
        "updatedAt": _iso_to_epoch_ms(v1["update_time"]),
        "ownerId": owner_id,
        "orgId": 0,
        "jsonType": "vlan-profile",
        "name": v1["name"],
        "predefined": False,
        "enableClassification": v1["enable_classification"],
        "classifiedEntries": entries,
        "defVlanId": v1["default_vlan_id"],
    }


def attach_vlan_attributes_v0(client, policy_id, vlan_cfg, vlan_profile_ids):
    """Populate the policy's Switching/Routing > VLAN Attribute table —
    CONFIRMED REAL 2026-08-16 from .docs/vlan-add.json. This is a
    SEPARATE step from VLAN classification (5c above): that made the
    VLAN Profile object itself classification-aware; this attaches it to
    THIS policy's own switching config, which is what actually shows up
    in the real UI's "VLAN Attributes" table (empty until this runs — the
    user caught the gap from a screenshot of that exact empty table).
    igmpSnooping/dhcpSnooping/etc. all default off — this lab has no real
    need for them yet, just carrying the real captured shape;
    `alwaysCreate: true` is real and required (flagged explicitly by the
    user from the capture) — it's what makes the VLAN provision even when
    no port on a device is currently tagged to it.

    Idempotent by name: CONFIRMED LIVE 2026-08-16 that a duplicate POST
    400's ("device.template.vlanAttributesSettings.vo.validator.dup.
    vlan.name", "Vlan with name '...' already present") rather than
    updating in place — existing entries are read back first and
    skipped, matching the pattern the rest of this file uses for objects
    with no real update verb.
    """
    owner_id = int(client.owner_id)
    path = f"/config/policy/switching/vlanattr/networkpolicy/{policy_id}"
    existing = client.v0_get(path)
    existing_list = existing.get("data", existing) if isinstance(existing, dict) else existing
    existing_names = {e.get("vlanObj", {}).get("name") for e in (existing_list or [])}

    count = 0
    for vp in vlan_cfg["vlan_profiles"]:
        if not vp.get("classification_rules"):
            continue
        if vp["name"] in existing_names:
            continue
        vid = vlan_profile_ids[vp["name"]]
        body = {
            "igmpSnooping": False,
            "dhcpSnooping": False,
            "alwaysCreate": True,
            "immediateLeave": False,
            "suppressRedundant": False,
            "dhcpSnoopingAction": "NONE",
            "jsonType": "vlan-attributes-entry",
            "ownerId": owner_id,
            "orgId": 0,
            "vlanObj": _build_vlan_obj_v0(client, vid),
        }
        client.v0_post(path, body, extra_params={"vocoLevel": 12})
        count += 1
    return count


def attach_classification_rules_v0(client, ssid_cfg, sid, policy_id, rule_ids_by_name, class_assignment_cache):
    """Attach classification rules to an SSID — real mechanism, confirmed
    2026-08-16 from a request the user captured in their own browser
    devtools while attaching a rule through the actual Platform ONE UI:

      PUT https://cloudapi.extremecloudiq.com/xiq/v0/config/ssid/ssidprofiles/networkpolicy/{policyId}/summary

    with a body carrying the SSID's summary fields (id/name/
    accessSecurityType/vlan) plus `classifiedEntries`, each wrapping a
    FULL nested classification-assignment object (see
    _fetch_class_assignment_v0) — not just its id.
    """
    names = ssid_cfg.get("classification_rules") or []
    if not names:
        return
    owner_id = int(client.owner_id)
    sec_type = ssid_cfg["access_security"]["security_type"]

    entries = []
    for name in names:
        rule_id = rule_ids_by_name[name]
        if rule_id not in class_assignment_cache:
            class_assignment_cache[rule_id] = _fetch_class_assignment_v0(client, rule_id)
        entries.append({"ownerId": owner_id, "classAsgn": class_assignment_cache[rule_id]})

    body = {
        "id": sid,
        "orgId": 0,
        "ownerId": owner_id,
        "name": ssid_cfg["name"],
        "accessSecurityType": sec_type,
        "vlan": ssid_cfg["user_profile"],
        "classifiedEntries": entries,
    }
    url = f"{client.v0_base_url}/config/ssid/ssidprofiles/networkpolicy/{policy_id}/summary?ownerId={owner_id}&ownerIds={owner_id}"
    r = client.session.put(url, json=body, timeout=20)
    if not r.ok:
        sys.exit(f"PUT (v0) classification attach for {ssid_cfg['name']} failed [{r.status_code}]: {r.text}")


# band -> (top-level radio-profile field, index into
# interfaceSettings.wirelessInterfaceSettings.entries, that entry's
# interfaceName). Confirmed live 2026-08-16 from the real captured create
# request (.docs/ap-template.json) — wifi0/1/2 are fixed, not configurable
# per the UI screenshot the user shared.
_AP_TEMPLATE_BANDS = {
    "24": ("radioProfile24g", 0, "wifi0"),
    "5": ("radioProfile5g", 1, "wifi1"),
    "6": ("radioProfileWifi2", 2, "wifi2"),
}


def load_ap_template_reference():
    path = os.path.join(DOCS_DIR, "ap-template.json")
    if not os.path.exists(path):
        sys.exit(
            f"Missing {path}. AP template creation needs a real captured request body "
            f"as a base (see device_templates.yaml header) — create one AP template by "
            f"hand in the Platform ONE UI, capture the POST /config/device/templates "
            f"request body, and save it there."
        )
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def build_ap_template_body_v0(reference, template_cfg, owner_id):
    """Build an AP device template create/update body from the real
    captured reference (see load_ap_template_reference), customized per
    template_cfg. Real mechanisms confirmed live 2026-08-16, see
    device_templates.yaml header: RF customization edits the embedded
    radio-profile objects directly (this repo's separate v1
    radio_profiles.yaml is NOT referenced here — different concept,
    same name); "band off" sets disableAllSsids on that band's interface
    entry rather than removing anything.
    """
    body = copy.deepcopy(reference)
    body["name"] = template_cfg["name"]
    body["productType"] = template_cfg.get("product_type", "AP_5010")
    body["ownerId"] = owner_id

    disabled = set(template_cfg.get("bands_disabled", []))
    powers = template_cfg.get("max_transmit_power", {})

    for band, (top_key, idx, iface_name) in _AP_TEMPLATE_BANDS.items():
        entry = body["interfaceSettings"]["wirelessInterfaceSettings"]["entries"][idx]
        assert entry["interfaceName"] == iface_name, f"unexpected interface order in reference for {iface_name}"
        entry["disableAllSsids"] = band in disabled
        if band in powers:
            body[top_key]["maxTransmitPower"] = powers[band]
            entry["radioProfile"]["maxTransmitPower"] = powers[band]

    return body


def upsert_ap_template_v0(client, template_cfg, reference, existing_by_name):
    name = template_cfg["name"]
    owner_id = int(client.owner_id)
    body = build_ap_template_body_v0(reference, template_cfg, owner_id)
    if name in existing_by_name:
        tid = existing_by_name[name]
        # Confirmed live 2026-08-16: PUT without the object's own `id` in
        # the body 500's ("core.service.unknown.error", no useful
        # message) even though the id is already in the URL — including
        # it in the body too fixes it.
        body["id"] = tid
        client.v0_put(f"/config/device/templates/{tid}", body)
        return tid, "updated"
    created = client.v0_post("/config/device/templates", body, extra_params={"vocoLevel": 10})
    return created["data"]["id"], "created"


# Switch device templates — CONFIRMED REAL 2026-08-16 from a request the
# user captured while building "A-5320-Test" (a Switch Engine 5320-16P-4XE
# template) by hand in the Platform ONE UI (.docs/sw-template.json). Same
# endpoint AP templates use (POST /config/device/templates, v0), real
# productType "SwitchEngine_5320_16P_4XE" (overturns the earlier
# SWE_5320_16P_4XE naming-convention guess). Real structural facts from
# the capture:
#
# 1. Ports are 0-indexed, flat, no per-unit prefix — confirmed for a
#    single-unit template: ETH 0-15 (the 16 PoE access ports), SFP 16-19
#    (the 4 XE uplink ports). Untested whether stack2/3 use the same flat
#    scheme or a per-unit-prefixed one (e.g. "2:0") — that's exactly the
#    kind of thing this repo doesn't guess at without a capture, so
#    Stack2/Stack3 stay unpushed until one exists.
# 2. TRIED Instant Port Profiles (LLDP-based dynamic port assignment)
#    first — abandoned after isolating a real, hard blocker via a
#    controlled A/B test: replaying the captured reference verbatim
#    succeeds, but swapping its Instant Port Profile's `id` for a
#    self-generated one reliably reproduces a 400
#    "simple.crud.service.can.not.update.other.vhm.object". Conclusion:
#    this endpoint can REFERENCE an already-existing Instant Port
#    Profile by id, but can't ORIGINATE a new one — that object type
#    needs its own real creation path, not found/captured. Full story in
#    ENGINEERING-NOTES.md. Replaced at the user's direction (2026-08-16)
#    with a static per-port layout instead, matching the Mist lab's own
#    style — see build_switch_template_body_v0.
# 3. Per the user: a port's role is just its `portType` sub-object,
#    swapped wholesale — "Access Port" (jsonType access-port) or "Trunk
#    Port" (jsonType trunk-port), both confirmed real. A THIRD "Uplink"
#    option also exists in the real UI (confirmed via screenshot) but was
#    dropped at the user's direction in favor of using `trunk` for both
#    the AP ports and the firewall uplink port — "forget about uplink,
#    its the same".
# 4. CONFIRMED LIVE 2026-08-16, after many failed customization attempts:
#    a trunk port can ONLY be used as Extreme's shared predefined object
#    (id 1107), completely UNMODIFIED — every attempt to customize it
#    (fresh id, fresh sub-object ids, a different `vlan` or
#    `allowedVlans`) 400'd identically, including reusing the tenant's
#    own real pre-existing custom trunk port verbatim in a different
#    template. See load_trunk_port_reference for the full A/B-tested
#    story. Unlike Access Port (which CAN be customized, though this
#    repo hasn't needed to yet), trunk ports are closer to the Instant
#    Port Profile situation — reference-only, not originate-able.
def load_switch_template_reference():
    path = os.path.join(DOCS_DIR, "sw-template.json")
    if not os.path.exists(path):
        sys.exit(
            f"Missing {path}. Switch template creation needs a real captured request "
            f"body as a base (see device_templates.yaml header) — create one by hand "
            f"in the Platform ONE UI, capture the POST /config/device/templates "
            f"request body, and save it there."
        )
    with open(path, encoding="utf-8") as f:
        raw = f.read()
    return json.loads(raw[raw.index("{"):])


def load_trunk_port_reference():
    """The real predefined "Trunk Port" object (id 1107, ownerId 0,
    predefined true), extracted from .docs/trunk.json — a request the
    user captured after setting a real port to Trunk Port in the UI.

    CONFIRMED LIVE 2026-08-16, after a long chain of failed customization
    attempts, all producing the identical opaque 400
    "portSettingsEntries[N].portType: must not be null": a trunk port can
    only be used by embedding this exact predefined object VERBATIM,
    unmodified, the same way access-port's own predefined id (1105) is
    reused as-is elsewhere in this file. Isolated via a definitive A/B
    test — replaying the same captured template with ONLY this
    predefined object (id 1107, all its real sub-ids intact) in one port
    group succeeded outright, while every attempt to customize it (fresh
    top-level id, fresh sub-object ids matching the real pattern a
    genuinely custom trunk port has, swapping `vlan`, swapping
    `allowedVlans`) failed identically — including reusing the tenant's
    OWN real pre-existing custom trunk port ("Uplink", id 1820297334459927)
    verbatim in a different template, which ALSO failed. Conclusion: a
    custom trunk port object can't be created OR moved between templates
    through this endpoint at all — only the shared predefined default is
    usable. That default already carries `allowedVlans: "all"` and native
    `vlan` "1" (Extreme's global default VLAN), which happens to satisfy
    this repo's actual requirement (AP ports need to carry every relevant
    VLAN) — just less precisely scoped than tagging 3 specific VLAN
    numbers, which isn't achievable here. See _port_type_trunk.
    """
    path = os.path.join(DOCS_DIR, "trunk.json")
    if not os.path.exists(path):
        sys.exit(f"Missing {path}. Needed for switch trunk-port templates.")
    with open(path, encoding="utf-8") as f:
        raw = f.read()
    body = json.loads(raw[raw.index("{"):])
    return body["portSettingsEntries"][0]["portType"]


def _port_type_access(access_port_type, owner_id):
    return copy.deepcopy(access_port_type)


# CONFIRMED REAL 2026-08-16 from .docs/add-port-type.json — a request the
# user captured saving a real "Access Port - Retail Staff" Port Type
# through the actual "Create Port Type" UI dialog. This resolved the two
# prior confirmed-live dead ends (silently re-linking to the predefined
# object by reusing its id, then a clean 400 core.service.missing.id when
# omitting it): Port Type is its OWN first-class object, created through
# its own dedicated endpoint, then only ever REFERENCED elsewhere by
# embedding its full shape — same pattern VLAN Profile/User Profile
# already use in this repo (see _build_vlan_obj_v0), just discovered
# later because push.py never needed a non-predefined Access Port until
# the SWE-5320-Retail-Stack1 empty-FDB investigation (see that template's
# comment in device_templates.yaml for the full story).
#
# Real endpoint: POST /config/port/accessports/ (trailing slash) with
# extra query params vocoLevel=6&baseType=access&deviceFamily=EXOS
# alongside the usual ownerId/ownerIds. Body has no `id` (fresh create,
# backend assigns one) — confirmed from the real capture, not guessed.
#
# The single most important finding in the capture: `defaultUserProfile`
# stays the untouched tenant default (id 36000, VLAN 1) even though
# `vlan` is set to a real BB-VP-* profile — the earlier assumption that
# defaultUserProfile needed to mirror `vlan` (in the now-removed
# _build_user_profile_obj_v0) was wrong. A plain access port's static
# VLAN tag is controlled by the top-level `vlan` field alone;
# defaultUserProfile only matters when enableUserProfileAssignment/
# enableRadiusAttributeUserProfileAssignment are on (dynamic, RADIUS- or
# rule-driven assignment — both false here, matching the capture).
_PORT_TYPE_CREATE_QUERY = {"vocoLevel": 6, "baseType": "access", "deviceFamily": "EXOS"}


def load_port_type_reference():
    path = os.path.join(DOCS_DIR, "add-port-type.json")
    if not os.path.exists(path):
        sys.exit(
            f"Missing {path}. A custom Access Port Type needs a real captured "
            f"request body as a base — create one by hand in the Platform ONE "
            f"UI's 'Create Port Type' dialog, capture the POST "
            f"/config/port/accessports/ request body, and save it there."
        )
    with open(path, encoding="utf-8") as f:
        raw = f.read()
    return json.loads(raw[raw.index("{"):])


def list_access_port_types_v0(client):
    resp = client.v0_get("/config/port/accessports/")
    return resp.get("data", resp) if isinstance(resp, dict) else resp


def upsert_access_port_type_v0(client, reference, name, vlan_profile_id):
    """Create-or-find-by-name a real, VLAN-tagged Access Port Type,
    naming convention `BB-PT-<suffix>` matching this repo's BB-VP-*/
    BB-UP-* 1:1 pattern (see build_switch_template_body_v0). No update
    verb confirmed for this object type (untested, and unnecessary so
    far — same "read back, skip if it already exists" pattern this file
    already uses for VLAN Attributes, since only `name`/`vlan` ever
    differ between entries and neither should change once created).
    Returns the FULL write-shape object (safe to embed directly into a
    switch template's portSettingsEntries), not the list endpoint's own
    entry — CONFIRMED that GET /config/port/accessports/ returns a
    thinner shape (defaultUserProfile.vlanId/qosSettingsId as bare ids,
    not nested objects) than what a create needs, the same read-vs-write
    mismatch already hit and fixed for AP/switch templates elsewhere in
    this file. Rebuilds from the real captured reference every time
    instead, merging in just the real id/createdAt/updatedAt.
    """
    vlan_obj = _build_vlan_obj_v0(client, vlan_profile_id)
    body = copy.deepcopy(reference)
    body.pop("id", None)
    body["name"] = name
    body["vlan"] = vlan_obj

    existing = list_access_port_types_v0(client)
    match = next((p for p in existing if p.get("name") == name), None)
    if match:
        body["id"] = match["id"]
        body["createdAt"] = match["createdAt"]
        body["updatedAt"] = match["updatedAt"]
        return body, "exists"

    resp = client.v0_post("/config/port/accessports/", body, extra_params=_PORT_TYPE_CREATE_QUERY)
    data = resp.get("data", resp) if isinstance(resp, dict) else resp
    body["id"] = data["id"]
    body["createdAt"] = data.get("createdAt", body.get("createdAt"))
    body["updatedAt"] = data.get("updatedAt", body.get("updatedAt"))
    return body, "created"


# CONFIRMED REAL 2026-08-16 from .docs/add-port-trunk.json — a request the
# user captured saving a real "Retail AP" Port Type (Trunk Port (802.1Q
# VLAN Tagging) usage) through the same "Create Port Type" UI dialog, with
# Allowed VLANs set explicitly to "30,32,35" instead of "all". This is the
# real, working alternative to the shared predefined Trunk Port (id 1107,
# allowedVlans: "all") that _port_type_trunk/load_trunk_port_reference use
# elsewhere — that object is genuinely reference-only/unmodifiable (see
# those functions), but a NEW custom trunk Port Type, created through its
# own endpoint the same way as a custom Access Port Type, works fine.
#
# Real endpoint: POST /config/port/trunkports/ (baseType=trunk, vs
# accessports'/baseType=access) — otherwise the same create pattern:
# no `id` in the body (fresh create), defaultUserProfile stays the
# untouched tenant default. The one real structural difference: there's
# no single VLAN Profile driving this object the way `vlan` does for an
# Access Port — native VLAN stays the reference's own default (VLAN 1,
# matching what the AP ports use today) and `allowedVlans` carries the
# EXPLICIT comma-delimited list of real VLAN TAG numbers (confirmed from
# the capture: "30,32,35", not vlan-profile object ids).
_TRUNK_PORT_TYPE_CREATE_QUERY = {"vocoLevel": 6, "baseType": "trunk", "deviceFamily": "EXOS"}


def load_trunk_port_type_reference():
    """Reference for a NEW, custom, explicitly-scoped Trunk Port Type —
    distinct from load_trunk_port_reference (which loads the shared
    PREDEFINED trunk object, id 1107, reference-only/unmodifiable). See
    the module comment above _TRUNK_PORT_TYPE_CREATE_QUERY.
    """
    path = os.path.join(DOCS_DIR, "add-port-trunk.json")
    if not os.path.exists(path):
        sys.exit(
            f"Missing {path}. A custom Trunk Port Type needs a real captured "
            f"request body as a base — create one by hand in the Platform ONE "
            f"UI's 'Create Port Type' dialog (Trunk Port (802.1Q VLAN Tagging) "
            f"usage, explicit Allowed VLANs instead of 'all'), capture the POST "
            f"/config/port/trunkports/ request body, and save it there."
        )
    with open(path, encoding="utf-8") as f:
        raw = f.read()
    return json.loads(raw[raw.index("{"):])


def list_trunk_port_types_v0(client):
    resp = client.v0_get("/config/port/trunkports/")
    return resp.get("data", resp) if isinstance(resp, dict) else resp


def upsert_trunk_port_type_v0(client, reference, name, allowed_vlans):
    """Create-or-find-by-name a real Trunk Port Type with an explicit
    VLAN list. `allowed_vlans` is the literal comma-delimited tag string
    (e.g. "30,32,35"), not a list of names/ids — build it from real VLAN
    tag numbers (vlan_profiles.yaml's `default_vlan_id`) before calling.
    Same "read back, skip if it already exists" idempotency pattern as
    upsert_access_port_type_v0, for the same reason (no update verb
    confirmed, and unnecessary — name/allowedVlans shouldn't change once
    created).
    """
    body = copy.deepcopy(reference)
    body.pop("id", None)
    body["name"] = name
    body["allowedVlans"] = allowed_vlans

    existing = list_trunk_port_types_v0(client)
    match = next((p for p in existing if p.get("name") == name), None)
    if match:
        body["id"] = match["id"]
        body["createdAt"] = match["createdAt"]
        body["updatedAt"] = match["updatedAt"]
        return body, "exists"

    resp = client.v0_post("/config/port/trunkports/", body, extra_params=_TRUNK_PORT_TYPE_CREATE_QUERY)
    data = resp.get("data", resp) if isinstance(resp, dict) else resp
    body["id"] = data["id"]
    body["createdAt"] = data.get("createdAt", body.get("createdAt"))
    body["updatedAt"] = data.get("updatedAt", body.get("updatedAt"))
    return body, "created"


def _port_type_trunk(trunk_port_reference, owner_id):
    """Returns the real predefined Trunk Port object UNMODIFIED — see
    load_trunk_port_reference for why customization isn't possible here.
    `owner_id` is accepted for signature symmetry with _port_type_access
    but unused; nothing in this object should be touched.
    """
    return copy.deepcopy(trunk_port_reference)


# _port_type_uplink was tried and dropped 2026-08-16 — the real UI has a
# distinct "Uplink" option (confirmed via screenshot) but jsonType
# "uplink-port" 400'd as unsupported and "uplink" alone was never
# isolated before the user simplified the design: "forget about uplink,
# its the same" — the firewall port uses the `trunk` role too now, same
# as the AP ports. See ENGINEERING-NOTES.md if Uplink is worth revisiting.


def build_switch_template_body_v0(reference, template_cfg, owner_id, client=None,
                                   vlan_profile_ids=None, vlan_tags=None):
    body = copy.deepcopy(reference)
    body["name"] = template_cfg["name"]
    body["ownerId"] = owner_id
    body["productType"] = template_cfg.get("product_type", "SwitchEngine_5320_16P_4XE")
    body["advancedSettings"]["productType"] = body["productType"]
    body["advancedSettings"]["ownerId"] = owner_id
    body["switchSettings"]["ownerId"] = owner_id
    body["vlanAttrSettings"]["ownerId"] = owner_id
    # No Instant Port Profile in this design — see module header point 2.
    body["portProfileSettingsEntries"] = []

    # Global Extreme predefined "Access Port" (id 1105) pulled from the
    # reference's own baseline — safe to reuse verbatim, confirmed real
    # and working.
    access_port_type = copy.deepcopy(reference["portSettingsEntries"][0]["portType"])
    # Only loaded if a port_plan group actually needs it — access-only
    # templates shouldn't require .docs/trunk.json to exist at all.
    trunk_port_type = None
    # Same laziness for the custom Access Port Type reference (see
    # upsert_access_port_type_v0) — only needed if some group actually
    # sets `vlan:`.
    port_type_reference = None
    # ...and for the custom Trunk Port Type reference (see
    # upsert_trunk_port_type_v0) — only needed if some group sets
    # `trunk_vlans:`.
    trunk_port_type_reference = None

    port_plan = template_cfg["port_plan"]
    entries = []
    for group in port_plan:
        ports = group["ports"]
        role = group["role"]
        # The reference never mixes ETH (0-15) and SFP (16-19) port
        # numbers within one details/ports group — each port_plan group
        # must stay on one side of that boundary too.
        if not (max(ports) < 16 or min(ports) >= 16):
            raise ValueError(f"switch port_plan group mixes ETH and SFP ports: {ports}")
        if role == "access":
            vlan_name = group.get("vlan")
            if vlan_name:
                if port_type_reference is None:
                    port_type_reference = load_port_type_reference()
                # BB-PT-<suffix> naming, 1:1 with BB-VP-<suffix> — same
                # convention as BB-UP-* in vlan_profiles.yaml.
                port_type_name = "BB-PT-" + vlan_name[len("BB-VP-"):]
                port_type, _ = upsert_access_port_type_v0(
                    client, port_type_reference, port_type_name, vlan_profile_ids[vlan_name])
            else:
                port_type = _port_type_access(access_port_type, owner_id)
        elif role == "trunk":
            trunk_vlans = group.get("trunk_vlans")
            if trunk_vlans:
                if trunk_port_type_reference is None:
                    trunk_port_type_reference = load_trunk_port_type_reference()
                port_type_name = group["port_type_name"]
                # `trunk_vlans: all` (a literal string, not a list) is
                # supported too — the real "Create Port Type" UI's own
                # tooltip confirms "all" is a valid Allowed VLANs value,
                # not just an explicit comma list. Useful for giving a
                # genuine "carry everything" uplink its own named,
                # per-format Port Type instead of reusing the shared
                # generic predefined Trunk Port (id 1107, see
                # _port_type_trunk/load_trunk_port_reference).
                if trunk_vlans == "all":
                    allowed_vlans = "all"
                else:
                    allowed_vlans = ",".join(str(vlan_tags[v]) for v in trunk_vlans)
                port_type, _ = upsert_trunk_port_type_v0(
                    client, trunk_port_type_reference, port_type_name, allowed_vlans)
            else:
                if trunk_port_type is None:
                    trunk_port_type = load_trunk_port_reference()
                port_type = _port_type_trunk(trunk_port_type, owner_id)
        else:
            raise ValueError(f"unknown switch port role: {role}")
        entries.append({
            "details": [{"ports": ports, "ownerId": owner_id}],
            "interfaceType": "SFP" if min(ports) >= 16 else "ETH",
            "portType": port_type,
            "portProfileId": None,
            "ownerId": owner_id,
        })
    body["portSettingsEntries"] = entries
    return body


def upsert_switch_template_v0(client, template_cfg, reference, existing_by_name,
                               vlan_profile_ids=None, vlan_tags=None):
    """CORRECTED 2026-08-16: this originally only checked existence by
    name and never updated an existing template — meaning a real
    port_plan bug (the physical/API port-indexing mix-up caught by the
    user from a live UI screenshot) stayed live even after the YAML was
    fixed, since re-running push.py just found the same broken object by
    name and left it alone. Now updates in place, same pattern already
    confirmed working for AP templates (v0 PUT, with the object's own
    real `id` included in the body — confirmed live 2026-08-16: PUT
    without it 500's with a useless generic error, same quirk AP
    templates already had).
    """
    name = template_cfg["name"]
    owner_id = int(client.owner_id)
    body = build_switch_template_body_v0(reference, template_cfg, owner_id, client, vlan_profile_ids, vlan_tags)
    if name in existing_by_name:
        tid = existing_by_name[name]
        body["id"] = tid
        client.v0_put(f"/config/device/templates/{tid}", body)
        return tid, "updated"
    resp = client.v0_post("/config/device/templates", body, extra_params={"vocoLevel": 10})
    return resp["data"]["id"], "created"


# Real query string captured verbatim from the "AP Template" tab
# (.docs/ap-add-with-rule.json) — includes a duplicate `vocoLevel` param
# (12 then 5) and every AP model XIQ supports. Not independently minimized
# or understood; replicated as-is rather than risk dropping something
# load-bearing after everything else this session that turned out to
# matter in non-obvious ways.
_AP_TEMPLATE_PROFILE_QUERY = (
    "vocoLevel=12&deviceFunction=Ap&vocoLevel=5&page.size=1000&productType="
    "AP_30,AP_120,AP_121,AP_122,AP_122X,AP_130,AP_141,AP_150W,AP_170,AP_230,"
    "AP_245X,AP_250,AP_302W,AP_305C,AP_305CX,AP_320,AP_330,AP_340,AP_350,AP_370,AP_390,"
    "AP_410C,AP_460C,AP_460S6C,AP_460S12C,AP_3000,AP_3000X,AP_4000,AP_4000U,AP_5010,AP_5010U,"
    "AP_5050D,AP_5020,AP_4020,AP_5022,AP_5022FX,AP_5022S6D,AP_5060D,AP_5060U,AP_4060,AP_4060X,"
    "AP_4020X,AP_4020FX,AP_5050U,AP_510C,AP_510CX,AP_550,AP_630,AP_650,AP_650X,AP_1130"
)


def attach_ap_templates_v0(client, policy_id, ap_templates_cfg, ap_reference,
                            classification_rule_ids, ap_template_ids):
    """Attach AP device templates to a policy, gated by classification
    rule — confirmed REAL and WORKING as of 2026-08-16, after a real dead
    end along the way worth recording: multiple attempts (varying method,
    URL shape, payload size, single vs. multiple entries) all had the
    server silently drop `classifiedEntries`, and the user reproducing it
    through the actual UI got the same result — a real 404 in devtools,
    with the UI showing the change anyway (optimistic update) until a
    hard refresh reverted it. That looked like a confirmed product bug.
    It wasn't: the fix was one missing field, `enableClassification: true`
    at the top level, absent from every attempt including the UI's own
    (mis-timed capture). Once added, both this script's POST and a fresh
    GET afterward confirmed it persists for real.

    Real endpoint: POST (not PUT — PUT 400's "not supported" at both the
    policy-scoped and item-level paths, tried both, even with
    enableClassification included) to the same policy-scoped URL as the
    read. POST does not update in place — it always returns a NEW profile
    id — but confirmed live this is harmless: the backend keeps exactly
    ONE device-template-profile per (policy, productType) and the old one
    is simply gone after the next POST (its own DELETE 400's afterward —
    not an error, there's nothing left to delete). Re-running this is
    safe; just don't expect the profile's own id to stay stable.
    """
    owner_id = int(client.owner_id)
    url = (f"{client.v0_base_url}/config/device/templateprofiles/networkpolicy/{policy_id}"
           f"?{_AP_TEMPLATE_PROFILE_QUERY}&ownerId={owner_id}&ownerIds={owner_id}")

    current = client.session.get(url, timeout=20)
    current.raise_for_status()
    current_list = current.json().get("data", [])
    # CONFIRMED LIVE 2026-08-16: this GET does NOT filter by
    # deviceFunction — see attach_switch_templates_v0's comment for the
    # full story. Harmless as long as AP is the ONLY device-template
    # function ever attached to a policy; broke for real the moment a
    # Switch profile also existed (current_list[0] started returning the
    # Switch profile instead), so filtering explicitly is required now.
    ap_profiles = [p for p in current_list if p.get("deviceFunction") == "Ap"]
    existing = ap_profiles[0] if ap_profiles else {}
    default_template = existing.get("defaultDeviceTemplate")

    entries = []
    for tpl_cfg in ap_templates_cfg:
        rule_name = tpl_cfg.get("classification_rule")
        if not rule_name:
            continue
        rule_id = classification_rule_ids[rule_name]
        class_asgn = _fetch_class_assignment_v0(client, rule_id)

        tid = ap_template_ids[tpl_cfg["name"]]
        thin = client.v0_get(f"/config/device/templates/{tid}")["data"]
        device_template = build_ap_template_body_v0(ap_reference, tpl_cfg, owner_id)
        device_template["id"] = thin["id"]
        device_template["createdAt"] = thin["createdAt"]
        device_template["updatedAt"] = thin["updatedAt"]

        entries.append({"ownerId": owner_id, "classAsgn": class_asgn, "deviceTemplate": device_template})

    body = {
        "ownerId": owner_id,
        "jsonType": "device-template-profile",
        "productType": "AP_5010",
        "deviceFunction": "Ap",
        "enableClassification": True,
        "classifiedEntries": entries,
        "defaultDeviceTemplate": default_template,
    }
    r = client.session.post(url, json=body, timeout=20)
    if not r.ok:
        sys.exit(f"POST (v0) AP template attach failed [{r.status_code}]: {r.text}")
    return len(entries)


# Switch-template-to-policy attach, by analogy to attach_ap_templates_v0
# above (same endpoint shape, same classification-rule-gated mechanism) —
# UNCONFIRMED for switches specifically, no capture exists of this exact
# operation for a switch template. Built from the AP version since it's
# the same underlying endpoint family (deviceFunction differs) and this
# repo's real AP attach mechanism has held up consistently.
#
# CONFIRMED LIVE 2026-08-16: the GET on this URL does NOT actually filter
# by `deviceFunction` — with AP templates already attached, the response
# comes back with the AP profile (productType AP_5010, deviceFunction Ap)
# regardless of the query's `deviceFunction=Switch`. Naively taking
# `current_list[0]` (fine for AP, since it was the first function ever
# attached to this policy) picked up the WRONG profile here and built a
# body claiming `productType: SwitchEngine_5320_16P_4XE` while embedding
# `defaultDeviceTemplate` from the AP profile — exactly the mismatch
# behind the 400 "The device product type does not match function in
# profile." Filtering the response for an entry whose OWN
# `deviceFunction` actually matches fixes it — see the list comprehension
# below (attach_ap_templates_v0 has the same latent bug, harmless in
# practice only because AP was attached before any other function
# existed on this policy).
_SWITCH_TEMPLATE_PROFILE_QUERY = (
    "vocoLevel=12&deviceFunction=Switch&vocoLevel=5&page.size=1000&"
    "productType=SwitchEngine_5320_16P_4XE"
)


def _inject_vlan_attributes_v0(client, device_template, policy_id):
    """CONFIRMED LIVE 2026-08-16, from a genuine working request the user
    captured (.docs/add-sw-template-to-np.json) — used ONLY on
    `defaultDeviceTemplate`, NOT on a classifiedEntry's own
    `deviceTemplate` (confirmed by direct JSON inspection of the real
    payload: the classifiedEntry's embedded SWE-5320-Retail-Stack1 has
    `vlanAttrSettings.vlanAttributesEntries: []`, empty, while
    `defaultDeviceTemplate`'s embedded SWE-5320-Default has all 10 real
    entries). An earlier version of this function applied it to both,
    which still 500'd — this asymmetry, not just "populate it somewhere",
    was the real missing piece. Also needed alongside this: the outer
    body's own `id`/`createdAt`/`updatedAt`, matching the EXISTING
    profile (an upsert-by-id, not a fresh always-new create) — see the
    body construction below.
    """
    path = f"/config/policy/switching/vlanattr/networkpolicy/{policy_id}"
    existing = client.v0_get(path)
    existing_list = existing.get("data", existing) if isinstance(existing, dict) else existing
    device_template = copy.deepcopy(device_template)
    vlan_attr = device_template.setdefault("vlanAttrSettings", {})
    vlan_attr["vlanAttributesEntries"] = existing_list or []
    vlan_attr.pop("vlanAttributesEntryIds", None)
    return device_template


def attach_switch_templates_v0(client, policy_id, switch_templates_cfg,
                                classification_rule_ids, switch_template_ids,
                                vlan_profile_ids=None, vlan_tags=None):
    owner_id = int(client.owner_id)
    url = (f"{client.v0_base_url}/config/device/templateprofiles/networkpolicy/{policy_id}"
           f"?{_SWITCH_TEMPLATE_PROFILE_QUERY}&ownerId={owner_id}&ownerIds={owner_id}")

    current = client.session.get(url, timeout=20)
    current.raise_for_status()
    current_list = current.json().get("data", [])
    switch_profiles = [p for p in current_list if p.get("deviceFunction") == "Switch"]
    existing = switch_profiles[0] if switch_profiles else {}
    default_template = existing.get("defaultDeviceTemplate")

    # CONFIRMED LIVE 2026-08-16 — the actual root cause of every "500
    # core.service.unknown.error" this endpoint gave, found only via a
    # recursive diff against a real captured working request
    # (.docs/add-sw-template-to-np.json): `GET /config/device/templates/
    # {id}` returns a SUMMARY/read shape (portTypeId, detailIds,
    # mgmtInterfaceSettingsId, dhcpSnoopingSettingsId, elrpSettingsId,
    # commonSettingsId, vlanAttributesEntryIds — bare id references), NOT
    # the full nested write shape (portType, details,
    # mgmtInterfaceSettings, etc.) this endpoint needs when embedding a
    # deviceTemplate inside classifiedEntries/defaultDeviceTemplate. Same
    # class of bug AP templates already had a fix for
    # (build_ap_template_body_v0 rebuilds from the real reference rather
    # than trusting a live GET) — switches needed the identical fix,
    # rebuilding via build_switch_template_body_v0 and merging in just
    # the real id/createdAt/updatedAt from a thin GET, rather than
    # embedding the thin GET's own (wrong-shaped) content directly.
    switch_reference = load_switch_template_reference()

    def _full_device_template(tpl_cfg, real_id):
        full = build_switch_template_body_v0(switch_reference, tpl_cfg, owner_id, client, vlan_profile_ids, vlan_tags)
        thin = client.v0_get(f"/config/device/templates/{real_id}")["data"]
        full["id"] = thin["id"]
        full["createdAt"] = thin["createdAt"]
        full["updatedAt"] = thin["updatedAt"]
        return full

    # At the user's direction (2026-08-16): a real, ruleless
    # `SWE-5320-Default` template is the policy's fallback for the whole
    # productType, distinct from format-specific ones like Retail — not
    # reusing a rule-gated template as its own default (an earlier,
    # narrower version of this function did that as a stopgap before this
    # template existed; matches the real 400 "defaultDeviceTemplate: must
    # not be null" this endpoint gives when nothing ruleless exists yet).
    for tpl_cfg in switch_templates_cfg:
        if "port_plan" not in tpl_cfg or tpl_cfg.get("classification_rules") or tpl_cfg.get("classification_rule"):
            continue
        name = tpl_cfg["name"]
        if name in switch_template_ids:
            default_template = _full_device_template(tpl_cfg, switch_template_ids[name])
            # CONFIRMED from the real capture: `defaultDeviceTemplate` (and
            # only that one, not classifiedEntries' own deviceTemplate)
            # needs its vlanAttrSettings populated with the real,
            # policy-level VLAN Attributes list — see
            # _inject_vlan_attributes_v0.
            default_template = _inject_vlan_attributes_v0(client, default_template, policy_id)
            break

    entries = []
    for tpl_cfg in switch_templates_cfg:
        if "port_plan" not in tpl_cfg:
            continue
        name = tpl_cfg["name"]
        if name not in switch_template_ids:
            continue
        # Retail's switch templates are shared across two formats
        # (Standalone + Mall, same as the SSIDs) so use plural
        # `classification_rules:`, unlike AP templates' singular
        # `classification_rule:` (1:1 per format) — one classifiedEntry
        # per rule, same deviceTemplate object reused across entries.
        rule_names = tpl_cfg.get("classification_rules") or ([tpl_cfg["classification_rule"]] if tpl_cfg.get("classification_rule") else [])
        rule_names = [r for r in rule_names if r in classification_rule_ids]
        if not rule_names:
            continue

        device_template = _full_device_template(tpl_cfg, switch_template_ids[name])
        for rule_name in rule_names:
            rule_id = classification_rule_ids[rule_name]
            class_asgn = _fetch_class_assignment_v0(client, rule_id)
            entries.append({"ownerId": owner_id, "classAsgn": class_asgn, "deviceTemplate": device_template})

    if not entries and default_template is None:
        return 0

    body = {
        "ownerId": owner_id,
        "jsonType": "device-template-profile",
        "productType": "SwitchEngine_5320_16P_4XE",
        "deviceFunction": "Switch",
        "enableClassification": True,
        "classifiedEntries": entries,
        "defaultDeviceTemplate": default_template,
    }
    # CONFIRMED LIVE 2026-08-16: also needed, alongside the vlanAttrSettings
    # fix above — including the EXISTING profile's own id/createdAt/
    # updatedAt (an upsert-by-id pattern, not a fresh always-new create)
    # when one already exists. Without this the identical body (with
    # vlanAttrSettings fixed) still 500's; with it, it matches the real
    # captured payload and succeeds.
    if existing:
        body["id"] = existing["id"]
        body["createdAt"] = existing["createdAt"]
        body["updatedAt"] = existing["updatedAt"]
    r = client.session.post(url, json=body, timeout=20)
    if not r.ok:
        sys.exit(f"POST (v0) switch template attach failed [{r.status_code}]: {r.text}")
    return len(entries)


def load_state():
    # "ssids" tracks every SSID push.py has touched (created OR merely
    # configured after finding it pre-existing) — used to look objects up
    # by name on re-runs. "ssids_created" is the subset push.py actually
    # created via create_ssid_v0 — the only ones teardown.py should ever
    # delete. Keeping these separate matters now that SSID creation is
    # real: a pre-existing SSID someone else made (found, not created)
    # must never be deleted just because push.py configured it.
    state = {"vlan_profiles": {}, "user_profiles": {}, "radio_profiles": {},
              "cloud_config_groups": {}, "classification_rules": {},
              "site_groups": {}, "sites": {}, "buildings": {}, "floors": {},
              "network_policies": {}, "ssids": {}, "ssids_created": {},
              "ap_templates": {}, "switch_templates": {}, "radius_servers": {}}
    if os.path.exists(STATE_PATH):
        with open(STATE_PATH, encoding="utf-8") as f:
            state.update(json.load(f))
    return state


def save_state(state):
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    with open(STATE_PATH, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


# Confirmed live 2026-08-15: Site_Group creation goes through the generic,
# type-agnostic pair of paths — POST /locations to create (disambiguated
# by a `type` field) and PUT /locations/{id} to update. CORRECTED
# 2026-08-16: this generic endpoint is NOT how SITE/BUILDING/FLOOR get
# created — see upsert_typed_location() below for those. The type-named
# item path (/locations/site-groups/{id}) LOOKS like a real per-type route
# from its own OPTIONS response (Allow: PUT,DELETE,OPTIONS) but a live PUT
# against it 404's — that Allow header was a red herring for Site_Group
# specifically. Existing Site_Groups still have to be found via
# /locations/tree (p1_client.list_locations_by_type) — no singular typed
# GET list path has been found/tried for Site_Group the way there was for
# site/building/floor.
def upsert_location(client, node_type, name, parent_id, extra=None, tree=None):
    # tree lets a caller pass an already-fetched /locations/tree so a loop
    # over many Site_Groups doesn't refetch the whole tenant tree once per
    # object — a real, avoidable slowdown on a shared tenant with a lot of
    # existing location data (see run()'s site_groups loop).
    existing = {n["name"]: n for n in client.list_locations_by_type(node_type, tree=tree)}
    body = {"name": name, "type": node_type, "parent_id": parent_id, **(extra or {})}
    if name in existing:
        nid = existing[name]["id"]
        client.update(f"/locations/{nid}", body)
        return nid, "updated"
    created = client.post("/locations", body)
    return created["id"], "created"


# CONFIRMED REAL 2026-08-16, from the user's own already-working
# automation (.docs/xiq_sites.py, .docs/xiq_add_buildings_and_floors.py —
# real production scripts dated Oct 2025). SITE/BUILDING/FLOOR each have
# their own typed collection path — POST /locations/site,
# /locations/building, /locations/floor (singular) — completely separate
# from the generic /locations endpoint Site_Group uses. No update endpoint
# has been confirmed for these types (the reference scripts are
# create-if-missing, matching by name or a 409, not full upsert), so this
# is create-if-missing too, not a real update-in-place.
COUNTRY_CODES = {"US": 840}


def _address_body(address_str):
    # Confirmed live 2026-08-16: POST /locations/building 500's "City is
    # required for a building" when city comes back blank — the reference
    # scripts' own city-blank fallback (for a plain address string) isn't
    # actually safe against this API's real validation. This repo's
    # addresses are all "<city stuff>, <ST>, USA" — split from the right:
    # last segment is the country (discarded, no structured field for it
    # was seen), second-to-last is state, everything else joined back is
    # city (covers the two addresses with a venue name prefix, e.g.
    # "Scottsdale Fashion Square, Scottsdale, AZ, USA").
    parts = [p.strip() for p in (address_str or "").split(",") if p.strip()]
    if len(parts) >= 3:
        city, state = ", ".join(parts[:-2]), parts[-2]
    elif len(parts) == 2:
        city, state = parts[0], parts[1]
    else:
        city, state = (parts[0] if parts else ""), ""
    return {"address": address_str or "", "address2": "", "city": city, "state": state, "postal_code": ""}


def build_site_body(site):
    return {
        "countryCode": COUNTRY_CODES.get(site.get("country_code", "US"), 840),
        "address": _address_body(site.get("address")),
        "latitude": 0,
        "longitude": 0,
    }


def build_building_body(site_address):
    return {
        "address": _address_body(site_address),
        "latitude": 0,
        "longitude": 0,
    }


def build_floor_body():
    return {
        "environment": "AUTO_ESTIMATE",
        "db_attenuation": 0,
        "measurement_unit": "FEET",
        "installation_height": 0,
        "map_size_width": 10,
        "map_size_height": 10,
        "map_name": "",
    }


def upsert_typed_location(client, node_type, name, parent_id, extra=None, existing=None):
    # Matches on (name, parent_id), NOT name alone — buildings and floors
    # in this lab intentionally reuse the same default name ("Main", "1")
    # across every site, so a name-only match would find site A's
    # "Main" building while creating site B's and silently reuse the
    # wrong id. `existing` lets a caller pass an already-fetched list
    # (see run()) so a loop over many sites doesn't refetch the whole
    # collection once per site — real, avoidable overhead otherwise.
    existing = client.get_all_typed_location(node_type) if existing is None else existing
    match = next((n for n in existing if n.get("name") == name and n.get("parent_id") == parent_id), None)
    if match:
        return match["id"], "found"
    body = {"name": name, "parent_id": parent_id, **(extra or {})}
    created = client.post(f"/locations/{node_type}", body)
    existing.append(created)
    return created["id"], "created"


def main():
    client = P1Client()
    state = load_state()
    secrets = load_secrets()
    # State is saved in `finally` so that a real object created against
    # the live tenant is always recorded even if a LATER step in this same
    # run fails and calls sys.exit — confirmed the hard way on 2026-08-15:
    # several earlier runs created dozens of real objects but died before
    # reaching the save_state() call at the end, leaving
    # state/created_objects.json completely empty despite live objects
    # existing. teardown.py can only ever delete what's recorded here.
    try:
        run(client, state, secrets)
    finally:
        save_state(state)
        print(f"\nState written to {STATE_PATH}")

    print("Note: policies/SSIDs/AP/switch templates are created but not assigned to any real")
    print("device — Platform ONE's confirmed device-binding is per-device (PUT /devices/{id}/policy,")
    print("PUT /devices/{id}/location). Claim a device into a site and assign its policy/template")
    print("by hand, same scope boundary as AP claiming in the Mist lab.")


def run(client, state, secrets):
    locations = load("locations")
    vlan_cfg = load("vlan_profiles")
    # name -> real VLAN tag number, for switch port_plan groups that need
    # an explicit VLAN list (trunk_vlans:) rather than a VLAN Profile
    # object id — see upsert_trunk_port_type_v0.
    vlan_tags = {vp["name"]: vp["default_vlan_id"] for vp in vlan_cfg["vlan_profiles"]}
    radio_profiles = load("radio_profiles")
    device_templates_cfg = load("device_templates")["device_templates"]
    ccg_cfg = load("cloud_config_groups")
    classification_cfg = load("classification_rules")
    policies_cfg = load("network_policies")
    radius_cfg = load("radius")

    # 1. VLAN profiles. enable_classification/classified_entries aren't in
    # the YAML (they're not part of this lab's intent) but the real API
    # requires enable_classification to be present and non-null on create
    # — confirmed live 2026-08-15 via a 400 from POST /vlan-profiles
    # ("XiqCreateVlanProfileRequest... enableClassification... must not be
    # null"). Defaulted here rather than repeated in every YAML entry.
    for vp in vlan_cfg["vlan_profiles"]:
        body = {"enable_classification": False, "classified_entries": [], **clean(vp)}
        vid, action = client.upsert_by_name("/vlan-profiles", vp["name"], body)
        state["vlan_profiles"][vp["name"]] = vid
        print(f"[vlan_profile] {vp['name']}: {action} ({vid})")

    # 2. User profiles. POST body shape (nested vlan_profile vs.
    # vlan_profile_id) is UNCONFIRMED — see vlan_profiles.yaml. This sends
    # vlan_profile_id as the best-effort guess.
    for up in vlan_cfg["user_profiles"]:
        body = clean(up)
        body["vlan_profile_id"] = state["vlan_profiles"][up["vlan_profile"]]
        uid, action = client.upsert_by_name("/user-profiles", up["name"], body)
        state["user_profiles"][up["name"]] = uid
        print(f"[user_profile] {up['name']}: {action} ({uid})")

    # 3. Radio profiles — one per band now, matches the real object shape.
    for rp in radio_profiles["radio_profiles"]:
        rid, action = client.upsert_by_name("/radio-profiles", rp["name"], clean(rp))
        state["radio_profiles"][rp["name"]] = rid
        print(f"[radio_profile] {rp['name']}: {action} ({rid})")

    # 3a. RADIUS servers (/radius-servers/external) — real, documented v1
    # endpoint, see radius.yaml header. Needed before SSID configuration
    # (step 6 below) since DOT1X SSIDs reference a real server id.
    for rs in radius_cfg["radius_servers"]:
        rsid, action = client.upsert_by_name("/radius-servers/external", rs["name"], clean(rs))
        state["radius_servers"][rs["name"]] = rsid
        print(f"[radius_server] {rs['name']}: {action} ({rsid})")

    # 3b. AP device templates — real, confirmed working (v0 API), found
    # from a request the user captured while creating one by hand in the
    # Platform ONE UI. NOT the same "radio profile" concept as step 3
    # above — see device_templates.yaml header and build_ap_template_body_v0.
    #
    # Existing-by-name lookup uses this repo's OWN state tracking, not a
    # fresh server-side list — confirmed live 2026-08-16 that GET
    # /config/device/templates hard-caps at 100 items (this tenant has 370
    # total, almost all Extreme's own predefined-per-model templates) with
    # no query param (offset/size/name/filter/search/q all tried) that
    # changes what comes back. Our own templates, created near the end,
    # never appear in that first page. Real pagination mechanism not
    # found — trusting state/created_objects.json instead is more
    # reliable here than guessing further at an unresponsive API.
    ap_reference = load_ap_template_reference()
    existing_templates = dict(state["ap_templates"])
    for tpl in device_templates_cfg["ap_templates"]:
        tid, action = upsert_ap_template_v0(client, tpl, ap_reference, existing_templates)
        state["ap_templates"][tpl["name"]] = tid
        print(f"[ap_template] {tpl['name']}: {action} ({tid})")

    # 3c. Switch device templates — pushed for whichever entries carry a
    # `port_plan:` block AND use only CONFIRMED-working port roles.
    # `access` and `trunk` are both confirmed real now (trunk only as
    # Extreme's unmodified predefined object — see
    # load_trunk_port_reference for the full story). client.v0_post
    # sys.exit's on any real API failure (this repo's fail-fast
    # convention), so a template using a genuinely unconfirmed role would
    # abort the whole push run rather than fail cleanly — still skipped
    # per-item for anything outside this set, same as the still-fully-
    # speculative templates below it in the list.
    SWITCH_PORT_ROLES_CONFIRMED = {"access", "trunk"}
    switch_reference = None
    for tpl in device_templates_cfg.get("switch_templates", []):
        roles = {g["role"] for g in tpl.get("port_plan", [])}
        if "port_plan" not in tpl:
            print(f"[switch_template] {tpl['name']}: skipped — design not yet pushed, see device_templates.yaml header")
            continue
        if not roles <= SWITCH_PORT_ROLES_CONFIRMED:
            unconfirmed = roles - SWITCH_PORT_ROLES_CONFIRMED
            print(f"[switch_template] {tpl['name']}: skipped — uses unconfirmed port role(s) {sorted(unconfirmed)}, see ENGINEERING-NOTES.md")
            continue
        if switch_reference is None:
            switch_reference = load_switch_template_reference()
        tid, action = upsert_switch_template_v0(client, tpl, switch_reference, state["switch_templates"],
                                                 state["vlan_profiles"], vlan_tags)
        state["switch_templates"][tpl["name"]] = tid
        print(f"[switch_template] {tpl['name']}: {action} ({tid})")

    # 4. Cloud Config Groups (/ccgs) — real, confirmed working endpoint.
    # Real constraint, confirmed live 2026-08-16 via a 400
    # ("cloudconfiggroup.vo.validator.missing.device.ids"): a CCG cannot
    # be CREATED with an empty device_ids array — at least one real
    # device id is required. None of our BB- sites have real hardware
    # claimed yet (same scope boundary as everywhere else in this repo —
    # see README "Deploying real hardware"), so none of these can be
    # created until that's true. Skipped cleanly rather than sending a
    # request known to fail; once a real device is claimed into e.g. a
    # retail site, add its device id to the relevant group in
    # cloud_config_groups.yaml and re-run.
    existing_ccgs = {c["name"]: c["id"] for c in client.get_all("/ccgs")}
    for ccg in ccg_cfg["cloud_config_groups"]:
        name = ccg["name"]
        if name not in existing_ccgs and not ccg.get("device_ids"):
            print(f"[cloud_config_group] {name}: skipped — needs >=1 real device_id to create, see comment above")
            continue
        cid, action = client.upsert_by_name("/ccgs", name, clean(ccg))
        state["cloud_config_groups"][name] = cid
        print(f"[cloud_config_group] {name}: {action} ({cid})")

    # 5. Site Groups, nested under the tenant's own top-level root.
    # Confirmed live 2026-08-15: POST /locations rejects a null parentId
    # ("must not be null") — there's no way to create a true new root via
    # this endpoint. The existing tree has exactly one root Site_Group
    # already (this tenant's own top-level container, siblings of which
    # already include their own "Lab" group) — our BB- site groups attach
    # there as new siblings rather than trying to be roots themselves.
    tree_roots = client.location_tree()
    tree_roots = tree_roots if isinstance(tree_roots, list) else [tree_roots]
    tenant_root_id = tree_roots[0]["id"]
    print(f"[locations] attaching BB- site groups under root '{tree_roots[0]['name']}' ({tenant_root_id})")

    for sg in locations["site_groups"]:
        sgid, action = upsert_location(client, "Site_Group", sg["name"], tenant_root_id, tree=tree_roots)
        state["site_groups"][sg["name"]] = sgid
        print(f"[site_group] {sg['name']}: {action} ({sgid})")

    # 5b. Classification Rules (/classification-rules) — real, confirmed
    # working endpoint. Switched from Cloud Config Group to Site Group as
    # the classification basis at the user's direction — Site Groups
    # already exist (just created above), unlike CCGs which can't be
    # created without a real device (see 4.). Real request field is
    # `classification_type_id`, NOT `classification_id` (the read side's
    # name for the same concept) — found via two live validation errors,
    # see classification_rules.yaml header.
    for cr in classification_cfg["classification_rules"]:
        sg_name = cr["site_group"]
        sg_id = state["site_groups"][sg_name]
        body = {
            "name": cr["name"],
            "classifications": [{
                "classification_type": "CLASSIFICATION_TYPE_LOCATION",
                "match": True,
                "classification_type_id": sg_id,
                "value": sg_name,
            }],
        }
        rid, action = client.upsert_by_name("/classification-rules", cr["name"], body)
        state["classification_rules"][cr["name"]] = rid
        print(f"[classification_rule] {cr['name']}: {action} ({rid})")

    # 5c. VLAN Profile classification — real, documented v1 fields
    # (`enable_classification`, `classified_entries`), see
    # vlan_profiles.yaml header for the full story of how this was
    # missed initially (this repo defaulted both to false/[] at create
    # time and never revisited them) and corrected by the user with a
    # screenshot of a real VLAN object's own classification UI. Runs
    # here, not in step 1, because it needs real classification rule ids
    # that don't exist until step 5b just above. `client.update()` picks
    # PATCH for /vlan-profiles/{id} (confirmed live 2026-08-15 — this is
    # the one object type that only allows PATCH, not PUT) — but PATCH
    # here is NOT a true partial patch: confirmed live 2026-08-16, a body
    # with only enable_classification/classified_entries 400's with
    # `XiqUpdateVlanProfileRequest`'s `name`/`defaultVlanId` both
    # "must not be null" — the endpoint validates the whole request
    # object, so name/default_vlan_id have to be resent alongside the
    # classification fields even though they aren't changing.
    for vp in vlan_cfg["vlan_profiles"]:
        rule_names = [r for r in vp.get("classification_rules", []) if r in state["classification_rules"]]
        if not rule_names:
            continue
        vid = state["vlan_profiles"][vp["name"]]
        entries = [
            {"classification_rule_id": state["classification_rules"][r], "vlan_id": vp["default_vlan_id"]}
            for r in rule_names
        ]
        body = {
            "name": vp["name"],
            "default_vlan_id": vp["default_vlan_id"],
            "enable_classification": True,
            "classified_entries": entries,
        }
        client.update(f"/vlan-profiles/{vid}", body)
        print(f"[vlan_profile] {vp['name']}: classified via {', '.join(rule_names)}")

    if not SITE_TYPE_CREATE_CONFIRMED:
        print(f"[site] skipped {len(locations['sites'])} site(s) — true SITE-type creation not confirmed, see module header")
    else:
        site_defaults = locations.get("site_defaults", {})
        default_building_name = locations.get("default_building_name", "Main")
        default_floor_name = locations.get("default_floor_name", "1")
        # Fetched once and reused across the whole loop below (each is a
        # plain list, mutated in place by upsert_typed_location as it
        # creates new ones) rather than re-fetching the full collection
        # once per site — see upsert_typed_location's comment.
        existing_sites = client.get_all_typed_location("site")
        existing_buildings = client.get_all_typed_location("building")
        existing_floors = client.get_all_typed_location("floor")
        for raw_site in locations["sites"]:
            site = {**site_defaults.get(raw_site.get("site_group"), {}), **raw_site}
            parent_id = state["site_groups"].get(site.get("site_group"))
            sid, action = upsert_typed_location(client, "site", site["name"], parent_id, build_site_body(site), existing=existing_sites)
            state["sites"][site["name"]] = sid
            print(f"[site] {site['name']}: {action} ({sid})")

            # Buildings/Floors are required, not optional depth — a device
            # can only be claimed into a Building or Floor, never a bare
            # Site (see locations.yaml header, 2026-08-16 correction). One
            # of each per site is the minimum needed for a real claim
            # target. State keys are scoped by site name since the default
            # building/floor names repeat across every site.
            building_name = site.get("building", default_building_name)
            bid, b_action = upsert_typed_location(client, "building", building_name, sid, build_building_body(site.get("address")), existing=existing_buildings)
            state["buildings"][f"{site['name']}/{building_name}"] = bid
            print(f"  [building] {building_name}: {b_action} ({bid})")

            floor_name = site.get("floor", default_floor_name)
            fid, f_action = upsert_typed_location(client, "floor", floor_name, bid, build_floor_body(), existing=existing_floors)
            state["floors"][f"{site['name']}/{building_name}/{floor_name}"] = fid
            print(f"  [floor] {floor_name}: {f_action} ({fid})")

    # 6. Network policies (thin shell objects) + their SSIDs.
    # SSID creation IS real (see create_ssid_v0's header for the full
    # story — found via captured browser traffic, no v1 endpoint exists
    # for it at all). For each SSID: create it via v0 if it doesn't
    # already exist by name, then configure it for real via configure_ssid()
    # (v1) and attach it to the policy via the real
    # POST /network-policies/{id}/ssids/:add endpoint (a bare array of
    # existing SSID ids).
    existing_ssids = {s["name"]: s["id"] for s in client.get_all("/ssids")}

    for pol in policies_cfg["network_policies"]:
        pol_body = {"name": pol["name"], "type": pol["type"], "description": pol.get("comment", "")}
        pid, action = client.upsert_by_name("/network-policies", pol["name"], pol_body)
        state["network_policies"][pol["name"]] = pid
        print(f"[network_policy] {pol['name']}: {action} ({pid})")

        ready_ssid_ids = []
        class_assignment_cache = {}
        for ssid_cfg in pol.get("ssids", []):
            name = ssid_cfg["name"]
            if name in existing_ssids:
                sid = existing_ssids[name]
                ssid_action = "found"
            else:
                sid = create_ssid_v0(client, ssid_cfg)
                existing_ssids[name] = sid
                state["ssids_created"][name] = sid
                ssid_action = "created"
            state["ssids"][name] = sid
            if configure_ssid(client, sid, ssid_cfg, state["user_profiles"], secrets, state["radius_servers"]):
                print(f"  [ssid] {name}: {ssid_action}, configured ({sid})")
                ready_ssid_ids.append(sid)
            else:
                print(f"  [ssid] {name}: {ssid_action} ({sid}) but not fully configured, see above — not attached to policy")

            if ssid_cfg.get("classification_rules"):
                attach_classification_rules_v0(
                    client, ssid_cfg, sid, pid, state["classification_rules"], class_assignment_cache)
                print(f"    classification rules: {', '.join(ssid_cfg['classification_rules'])}")

        if ready_ssid_ids:
            client.post(f"/network-policies/{pid}/ssids/:add", ready_ssid_ids)
            print(f"  attached {len(ready_ssid_ids)} SSID(s) to {pol['name']}")

        # 7. AP device templates -> policy, gated by classification rule.
        attached_count = attach_ap_templates_v0(
            client, pid, device_templates_cfg["ap_templates"],
            ap_reference, state["classification_rules"], state["ap_templates"])
        print(f"  attached {attached_count} AP template(s) to {pol['name']}")

        # 7b. VLAN Attributes -> policy's Switching/Routing table. See
        # attach_vlan_attributes_v0 — a real, separate step from 5c's
        # VLAN Profile classification.
        vlan_attr_count = attach_vlan_attributes_v0(client, pid, vlan_cfg, state["vlan_profiles"])
        print(f"  attached {vlan_attr_count} VLAN(s) to {pol['name']}'s Switching/Routing")

        # 7c. Switch device templates -> policy, same mechanism as AP
        # templates above. RESOLVED 2026-08-16 — see
        # attach_switch_templates_v0's own comments for the real root
        # cause (a read-vs-write shape mismatch) found via a genuine
        # captured working request, after a long chain of failed
        # hypotheses. Confirmed live via a fresh GET, both classification
        # rules attached — back to this repo's normal fail-fast
        # convention now that the cause is understood and fixed, not
        # wrapped defensively anymore.
        switch_attached_count = attach_switch_templates_v0(
            client, pid, device_templates_cfg.get("switch_templates", []),
            state["classification_rules"], state["switch_templates"],
            state["vlan_profiles"], vlan_tags)
        print(f"  attached {switch_attached_count} switch template(s) to {pol['name']}")

if __name__ == "__main__":
    main()
