"""Bootstrap + empirical-verification helper.

Corrected 2026-08-15/16 after real passes against a live tenant. GET
/locations/sites (the original guess) actually rejects GET outright — use
/locations/tree instead, which works and is what this script now calls.
Keep using this pattern before trusting any new object type this repo
doesn't already cover: GET the list endpoint first, and if that fails,
check whether the object only shows up nested in a tree/parent response
instead (as sites do here). Better still: check .docs/api-1.json first if
it's present — a real OpenAPI spec pulled from the tenant's own developer
portal beats endpoint-guessing every time (see network_policies.yaml's
header for how much that one file resolved in a single afternoon).
"""
import json

from p1_client import P1Client


def main():
    client = P1Client()

    print("GET /locations/tree ...")
    tree = client.location_tree()
    print(json.dumps(tree, indent=2)[:2000])

    print("\nSites found in the tree:")
    for s in client.list_locations_by_type("SITE"):
        print(f"  {s.get('name', '?'):40s} id={s.get('id')}")

    print("\nGET /radio-profiles (all pages) ...")
    for rp in client.get_all("/radio-profiles"):
        print(f"  {rp.get('name'):20s} radio_mode={rp.get('radio_mode')} predefined={rp.get('predefined')}")

    print("\nGET /network-policies (all pages) ...")
    for pol in client.get_all("/network-policies"):
        print(f"  {pol.get('name'):20s} type={pol.get('type')}")

    print("\nGET /ssids (all pages) ...")
    for ssid in client.get_all("/ssids"):
        sec = ssid.get("access_security", {})
        print(f"  {ssid.get('name'):20s} security_type={sec.get('security_type')} key_management={sec.get('key_management')}")

    print("\nGET /ccgs (all pages) ...")
    for ccg in client.get_all("/ccgs"):
        print(f"  {ccg.get('name'):30s} device_ids={ccg.get('device_ids')} read_only={ccg.get('read_only')}")

    print("\nGET /classification-rules (all pages) ...")
    for cr in client.get_all("/classification-rules"):
        types = [c.get("classification_type") for c in cr.get("classifications", [])]
        print(f"  {cr.get('name'):30s} types={types}")


if __name__ == "__main__":
    main()
