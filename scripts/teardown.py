"""Delete everything push.py created, using state/created_objects.json as
the source of truth (never deletes by name-prefix guessing).

Dry-run by default — prints what would be deleted. Pass --yes to actually
delete. SSIDs are handled specially: state["ssids"] tracks every SSID
push.py has touched (created OR merely configured after finding it
pre-existing), but only state["ssids_created"] — the subset push.py
actually created via the v0 API — is ever deleted here. An SSID push.py
found already existing (made by a human, or by another engineer in this
shared tenant) is never touched, even though push.py may have
reconfigured its mode/PSK/VLAN.

Deletion order goes most-dependent-first: SSIDs before the network
policies they're attached to, classification rules before the Cloud
Config Groups they reference, then locations (sites before site groups),
then radio/user/vlan profiles (user profiles reference vlan profiles, so
vlan profiles go last).
"""
import json
import os
import sys

from p1_client import P1Client

STATE_PATH = os.path.join(os.path.dirname(__file__), "..", "state", "created_objects.json")

DELETE_PLAN = [
    ("ssids_created", lambda c, i: c.v0_delete(f"/config/ssid/ssidprofiles/{i}")),
    ("classification_rules", lambda c, i: c.delete(f"/classification-rules/{i}")),
    ("cloud_config_groups", lambda c, i: c.delete(f"/ccgs/{i}")),
    ("network_policies", lambda c, i: c.delete(f"/network-policies/{i}")),
    # Sites and site groups both delete via the generic /locations/{id} —
    # confirmed live 2026-08-15 that the typed path (/locations/sites/{id})
    # 404's even though it looks valid from its own OPTIONS response; see
    # push.py's upsert_location header comment for the full story.
    ("sites", lambda c, i: c.delete(f"/locations/{i}")),
    ("site_groups", lambda c, i: c.delete(f"/locations/{i}")),
    ("radio_profiles", lambda c, i: c.delete(f"/radio-profiles/{i}")),
    ("user_profiles", lambda c, i: c.delete(f"/user-profiles/{i}")),
    ("vlan_profiles", lambda c, i: c.delete(f"/vlan-profiles/{i}")),
]


def main():
    if not os.path.exists(STATE_PATH):
        sys.exit(f"No state file at {STATE_PATH} — nothing tracked to delete. "
                  f"Nothing will be removed by name-guessing.")

    with open(STATE_PATH, encoding="utf-8") as f:
        state = json.load(f)

    dry_run = "--yes" not in sys.argv
    client = P1Client() if not dry_run else None

    total = 0
    for category, delete_fn in DELETE_PLAN:
        items = state.get(category, {})
        for name, obj_id in items.items():
            total += 1
            if dry_run:
                print(f"[dry-run] would delete {category}: {name} ({obj_id})")
            else:
                delete_fn(client, obj_id)
                print(f"[deleted] {category}: {name} ({obj_id})")

    configured_only = len(state.get("ssids", {})) - len(state.get("ssids_created", {}))
    if configured_only:
        print(f"\nNote: {configured_only} SSID(s) were found pre-existing and only "
              f"reconfigured by push.py, not created — those are NOT deleted here.")

    if dry_run:
        print(f"\n{total} objects would be deleted. Re-run with --yes to actually delete them.")
    else:
        os.remove(STATE_PATH)
        print(f"\n{total} objects deleted. {STATE_PATH} removed.")


if __name__ == "__main__":
    main()
