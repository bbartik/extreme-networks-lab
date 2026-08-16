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

# Confirmed live 2026-08-15: POST /locations silently ignores the `type`
# field entirely — sending type: "SITE" still creates a Site_Group (proven
# by reading the created object straight back from the POST response: it
# came back "type": "Site Group", not "SITE" — a disposable test object
# was created and deleted to confirm this, per HANDOFF Section 2.2). Every
# "site" this repo has created so far is actually a nested Site_Group
# folder, not a true SITE node. Skip further site creation until the real
# mechanism is found (most likely only discoverable via the actual web
# UI's network traffic) — re-attempting with the current logic just hits
# "folder cannot be saved because the name already exists" against the
# already-created (mistyped) folders.
SITE_TYPE_CREATE_CONFIRMED = False

# Keys that exist in the YAML for documentation/cross-referencing/local
# resolution but aren't real Platform ONE API fields — stripped before
# anything is sent.
NON_API_KEYS = {"comment", "site_group", "radio_profile", "device_template_ap",
                 "network_policy", "vars", "name_prefix", "vlan_profile",
                 "user_profile", "cloud_config_group", "classification_rules"}


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


def configure_ssid(client, sid, ssid_cfg, user_profile_ids, secrets):
    """Configure an EXISTING SSID (by real id) using the confirmed-real
    mode-setting endpoints found in the real OpenAPI spec (.docs/api-1.json,
    2026-08-16). Everything after bare creation — mode, PSK, VLAN (user
    profile), policy attachment — is real and scriptable via the v1 API.

    Returns True if fully configured (safe to attach to the policy), False
    if this SSID's mode needs an object type not explored this session
    (PPSK needs user_group_ids, DOT1X needs enable_idm or
    radius_server_group_id) — skipped with a clear message rather than
    guessed at.
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
    elif sec_type == "DOT1X":
        print(f"    skipped mode config — DOT1X needs enable_idm or a real radius_server_group_id (not explored this session)")
        return False
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
    existing = current_list[0] if current_list else {}
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
              "site_groups": {}, "sites": {}, "network_policies": {},
              "ssids": {}, "ssids_created": {}, "ap_templates": {}}
    if os.path.exists(STATE_PATH):
        with open(STATE_PATH, encoding="utf-8") as f:
            state.update(json.load(f))
    return state


def save_state(state):
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    with open(STATE_PATH, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


# Confirmed live 2026-08-15: creation and update of every location type
# both go through ONE generic, type-agnostic pair of paths — POST
# /locations to create (disambiguated by a `type` field) and PUT
# /locations/{id} to update, regardless of whether that id is a Site_Group,
# SITE, BUILDING, or FLOOR. The type-named paths (/locations/sites,
# /locations/site-groups, etc.) LOOK like real per-type item routes from
# their own OPTIONS response (Allow: PUT,DELETE,OPTIONS) but a live PUT
# against /locations/site-groups/{id} 404's — that Allow header was a red
# herring, not a real route. Existing objects still have to be found via
# /locations/tree (see p1_client.list_locations_by_type) since there's no
# GET list endpoint for any location type.
def upsert_location(client, node_type, name, parent_id, extra=None):
    existing = {n["name"]: n for n in client.list_locations_by_type(node_type)}
    body = {"name": name, "type": node_type, "parent_id": parent_id, **(extra or {})}
    if name in existing:
        nid = existing[name]["id"]
        client.update(f"/locations/{nid}", body)
        return nid, "updated"
    created = client.post("/locations", body)
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

    print("Note: policies/SSIDs/AP templates are created but not assigned to any device —")
    print("switch templates specifically are still not created (no endpoint found/captured")
    print("for those yet, see device_templates.yaml). Platform ONE's confirmed device-binding")
    print("is per-device (PUT /devices/{id}/policy, PUT /devices/{id}/location) — claim a")
    print("device into a site and assign its policy/template by hand, same scope boundary as")
    print("AP claiming in the Mist lab.")


def run(client, state, secrets):
    locations = load("locations")
    vlan_cfg = load("vlan_profiles")
    radio_profiles = load("radio_profiles")
    device_templates_cfg = load("device_templates")["device_templates"]
    ccg_cfg = load("cloud_config_groups")
    classification_cfg = load("classification_rules")
    policies_cfg = load("network_policies")

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
        sgid, action = upsert_location(client, "Site_Group", sg["name"], tenant_root_id)
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

    if not SITE_TYPE_CREATE_CONFIRMED:
        print(f"[site] skipped {len(locations['sites'])} site(s) — true SITE-type creation not confirmed, see module header")
    else:
        site_defaults = locations.get("site_defaults", {})
        for raw_site in locations["sites"]:
            site = {**site_defaults.get(raw_site.get("site_group"), {}), **raw_site}
            parent_id = state["site_groups"].get(site.get("site_group"))
            extra = {k: v for k, v in clean(site).items() if k != "name"}
            sid, action = upsert_location(client, "SITE", site["name"], parent_id, extra)
            state["sites"][site["name"]] = sid
            print(f"[site] {site['name']}: {action} ({sid})")

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
            if configure_ssid(client, sid, ssid_cfg, state["user_profiles"], secrets):
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

if __name__ == "__main__":
    main()
