#!/usr/bin/env python3
import argparse
import json
import os
import random
import sys
from pathlib import Path

import requests


# =========================
# Config
# =========================

DEFAULT_CONFIG_PATH = Path.home() / ".unifi_tone_rotation.json"
ROTATION_SLOTS = ["rotation_a", "rotation_b"]
MAX_DOORBELL_RINGTONES = 10  # hard stop if we can't free a slot


# =========================
# Helpers: config
# =========================

def load_config(path: Path = DEFAULT_CONFIG_PATH) -> dict:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_config(cfg: dict, path: Path = DEFAULT_CONFIG_PATH) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    print(f"Config saved to {path}")


# =========================
# Helpers: HTTP session
# =========================

def make_session(base_url: str, api_token: str) -> requests.Session:
    sess = requests.Session()
    sess.verify = False  # if you're using self-signed certs; otherwise set to True
    sess.headers.update({
        "Authorization": f"Bearer {api_token}",
    })
    # Normalize base_url (no trailing slash)
    if base_url.endswith("/"):
        base_url = base_url[:-1]
    sess.base_url = base_url  # type: ignore[attr-defined]
    return sess


# =========================
# UniFi Protect helpers
# =========================

def get_cameras(sess: requests.Session):
    resp = sess.get(f"{sess.base_url}/proxy/protect/api/cameras")
    resp.raise_for_status()
    return resp.json()


def is_doorbell(cam: dict) -> bool:
    flags = cam.get("featureFlags") or {}
    if flags.get("isDoorbell"):
        return True
    model = (cam.get("model") or "").lower()
    name = (cam.get("name") or "").lower()
    if "doorbell" in model or "doorbell" in name:
        return True
    return False


def get_ringtones(sess: requests.Session):
    resp = sess.get(f"{sess.base_url}/proxy/protect/api/files/ringtones")
    resp.raise_for_status()
    return resp.json()


def group_ringtones_by_original(files):
    grouped = {}
    for f in files:
        if f.get("type") != "ringtones":
            continue
        orig = f.get("originalName")
        if not orig:
            continue
        grouped.setdefault(orig, []).append(f)
    return grouped


def find_ringtones_by_original(files, original_name: str):
    """Return list of ringtone objects (all variants) for a given originalName."""
    return [
        f for f in files
        if f.get("type") == "ringtones"
        and f.get("originalName") == original_name
    ]


def delete_ringtone(sess: requests.Session, ringtone_id: str):
    # Matches what you observed: ignoreFileExtension=true deletes the logical pair
    url = f"{sess.base_url}/proxy/protect/api/files/ringtones/{ringtone_id}"
    resp = sess.delete(url, params={"ignoreFileExtension": "true"})
    resp.raise_for_status()


def upload_ringtone_from_file(sess: requests.Session, slot_name: str, file_path: Path):
    """
    Upload a ringtone for a given slot_name (e.g. 'rotation_a') using the audio from file_path.

    We send as multipart/form-data with a filename 'slot_name.mp3' so Protect
    uses originalName = slot_name. Response is a list of ringtone objects;
    we return (doorbell_tone, chime_tone) where each may be None.
    """
    url = f"{sess.base_url}/proxy/protect/api/files/ringtones"

    with file_path.open("rb") as f:
        # 'file' field name is a good guess for standard file upload;
        # if Protect uses a different form field, adjust here.
        files = {
            "file": (f"{slot_name}.mp3", f, "audio/mpeg"),
        }
        resp = sess.post(url, files=files)
    resp.raise_for_status()
    items = resp.json()

    doorbell_tone = None
    chime_tone = None
    for item in items:
        supported = (item.get("metadata") or {}).get("supportedBy") or []
        if "doorbell" in supported:
            doorbell_tone = item
        if "chime" in supported or "speaker" in supported:
            chime_tone = item

    return doorbell_tone, chime_tone


def get_camera(sess: requests.Session, cam_id: str):
    resp = sess.get(f"{sess.base_url}/proxy/protect/api/cameras/{cam_id}")
    resp.raise_for_status()
    return resp.json()


def patch_camera_ringtone(sess: requests.Session, cam_id: str, ringtone_id: str):
    """
    Patch camera speakerSettings.ringtoneId to ringtone_id.
    We mirror the UI-style PATCH: send key sub-objects, with ringtoneId changed.
    """
    cam = get_camera(sess, cam_id)

    payload = {
        "micVolume": cam.get("micVolume"),
        "name": cam.get("name"),
        "ledSettings": cam.get("ledSettings") or {},
        "ispSettings": cam.get("ispSettings") or {},
        "speakerSettings": cam.get("speakerSettings") or {},
        "homekitSettings": cam.get("homekitSettings") or {},
        "audioSettings": cam.get("audioSettings") or {},
        "recordingSettings": cam.get("recordingSettings") or {},
    }

    speaker = payload["speakerSettings"]
    speaker["ringtoneId"] = ringtone_id

    resp = sess.patch(
        f"{sess.base_url}/proxy/protect/api/cameras/{cam_id}",
        json=payload,
    )
    resp.raise_for_status()
    return resp.json()


# =========================
# Configure mode
# =========================

def configure(config_path: Path):
    cfg = load_config(config_path)

    base_url = cfg.get("base_url") or input("UniFi base URL (e.g. https://192.168.15.24): ").strip()
    api_token = cfg.get("api_token") or input("UniFi API token: ").strip()
    ringtone_dir = cfg.get("ringtone_directory") or input("Directory with mp3 files: ").strip()

    cfg["base_url"] = base_url
    cfg["api_token"] = api_token
    cfg["ringtone_directory"] = ringtone_dir

    sess = make_session(base_url, api_token)

    # Fetch & show cameras
    cams = get_cameras(sess)
    if not cams:
        print("No cameras found from Protect API; check your token / URL.")
        return

    print("\nDiscovered cameras:")
    indexed = []
    for i, cam in enumerate(cams):
        doorbell_flag = is_doorbell(cam)
        label = "[doorbell]" if doorbell_flag else "[camera]"
        print(f"{i}: {label} name={cam.get('name')} id={cam.get('_id') or cam.get('id')}")
        indexed.append(cam)

    print("\nSelect doorbells to participate in rotation.")
    print("Enter comma-separated indices (e.g. 0,2,3) or leave blank for none.")
    raw = input("Doorbells to rotate: ").strip()

    selected_ids = []
    if raw:
        for part in raw.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                idx = int(part)
            except ValueError:
                print(f"Ignoring invalid index: {part}")
                continue
            if idx < 0 or idx >= len(indexed):
                print(f"Ignoring out-of-range index: {idx}")
                continue
            cam = indexed[idx]
            cam_id = cam.get("_id") or cam.get("id")
            if not cam_id:
                print(f"Camera at index {idx} has no id, skipping.")
                continue
            selected_ids.append(cam_id)

    cfg["doorbell_ids"] = selected_ids

    save_config(cfg, config_path)


# =========================
# Rotation logic
# =========================

def pick_inactive_slot(sess: requests.Session, doorbell_ids, ringtones):
    """
    Determine which rotation slot is 'inactive' (safe to overwrite).

    Strategy:
      - Look up doorbell_ringtones with originalName in ROTATION_SLOTS.
      - For each doorbell, see which rotation slot (if any) it's currently using.
      - If both exist, choose the one NOT currently used by any doorbell.
      - If only one exists, the other is inactive.
      - If none exist, use the first slot.
    """
    # Map originalName -> list of ringtone objects
    grouped = group_ringtones_by_original(ringtones)

    existing_slots = {name for name in ROTATION_SLOTS if name in grouped}
    active_slot_ids = set()

    # Find current ringtoneIds on doorbells
    current_ringtone_ids = set()
    for cam_id in doorbell_ids:
        cam = get_camera(sess, cam_id)
        speaker = (cam.get("speakerSettings") or {})
        rid = speaker.get("ringtoneId")
        if rid:
            current_ringtone_ids.add(rid)

    # Map ringtone id -> originalName for rotation slots
    rot_id_to_slot = {}
    for slot in ROTATION_SLOTS:
        for r in grouped.get(slot, []):
            rid = r.get("id")
            if rid:
                rot_id_to_slot[rid] = slot

    for rid in current_ringtone_ids:
        slot = rot_id_to_slot.get(rid)
        if slot:
            active_slot_ids.add(slot)

    # Choose inactive slot
    for slot in ROTATION_SLOTS:
        if slot not in active_slot_ids:
            return slot

    # If both slots considered active (weird), just use the first one
    return ROTATION_SLOTS[0]


def count_doorbell_ringtones(ringtones):
    count = 0
    for f in ringtones:
        if f.get("type") != "ringtones":
            continue
        supported = (f.get("metadata") or {}).get("supportedBy") or []
        if "doorbell" in supported:
            count += 1
    return count


def run_rotation(config_path: Path):
    cfg = load_config(config_path)
    if not cfg:
        print(f"No config found at {config_path}. Run with --configure first.")
        sys.exit(1)

    base_url = cfg.get("base_url")
    api_token = cfg.get("api_token")
    ringtone_dir = cfg.get("ringtone_directory")
    doorbell_ids = cfg.get("doorbell_ids") or []

    if not base_url or not api_token or not ringtone_dir:
        print("Config missing base_url, api_token or ringtone_directory. Run with --configure.")
        sys.exit(1)

    if not doorbell_ids:
        print("No doorbells configured for rotation. Run with --configure to select them.")
        sys.exit(0)

    mp3_dir = Path(ringtone_dir)
    if not mp3_dir.is_dir():
        print(f"Configured ringtone_directory does not exist or is not a directory: {mp3_dir}")
        sys.exit(1)

    mp3_files = [p for p in mp3_dir.iterdir() if p.is_file() and p.suffix.lower() == ".mp3"]
    if not mp3_files:
        print(f"No .mp3 files found in directory {mp3_dir}")
        sys.exit(1)

    sess = make_session(base_url, api_token)

    # Fetch all ringtones
    ringtones = get_ringtones(sess)

    # Check ringtone count (doorbell-supported)
    doorbell_count = count_doorbell_ringtones(ringtones)
    print(f"Current doorbell-supported ringtone count: {doorbell_count}")

    grouped = group_ringtones_by_original(ringtones)

    # If we have too many and no rotation slots to delete, bail out
    existing_rotation_ringtones = []
    for slot in ROTATION_SLOTS:
        existing_rotation_ringtones.extend(grouped.get(slot, []))

    if doorbell_count >= MAX_DOORBELL_RINGTONES and not existing_rotation_ringtones:
        print(
            f"Error: already {doorbell_count} doorbell ringtones. "
            f"Please delete one in Protect before running this script."
        )
        sys.exit(1)

    # Pick inactive slot to overwrite
    slot_name = pick_inactive_slot(sess, doorbell_ids, ringtones)
    print(f"Using rotation slot: {slot_name}")

    # Delete old ringtone for this slot (if any)
    old_variants = grouped.get(slot_name, [])
    if old_variants:
        # Use any one id with ignoreFileExtension=true to delete the pair
        to_delete_id = old_variants[0]["id"]
        print(f"Deleting existing ringtone for slot '{slot_name}' (id={to_delete_id})...")
        delete_ringtone(sess, to_delete_id)

        # Refresh ringtone list & count after deletion
        ringtones = get_ringtones(sess)
        doorbell_count = count_doorbell_ringtones(ringtones)
        print(f"Doorbell ringtones after deletion: {doorbell_count}")

        if doorbell_count >= MAX_DOORBELL_RINGTONES:
            print(
                f"Error: still {doorbell_count} doorbell ringtones after deleting slot '{slot_name}'. "
                "Please delete one manually and try again."
            )
            sys.exit(1)

    # Pick random mp3
    chosen_file = random.choice(mp3_files)
    print(f"Uploading new ringtone for slot '{slot_name}' from: {chosen_file}")

    doorbell_tone, chime_tone = upload_ringtone_from_file(sess, slot_name, chosen_file)
    if not doorbell_tone:
        print("Upload succeeded but no doorbell-supported ringtone was returned. Aborting.")
        sys.exit(1)

    print(
        f"Uploaded doorbell ringtone: id={doorbell_tone['id']} "
        f"name={doorbell_tone['name']} originalName={doorbell_tone['originalName']}"
    )
    if chime_tone:
        print(
            f"Uploaded chime/speaker ringtone: id={chime_tone['id']} "
            f"name={chime_tone['name']} originalName={chime_tone['originalName']}"
        )

    new_ringtone_id = doorbell_tone["id"]

    # Set all configured doorbells to this ringtone
    for cam_id in doorbell_ids:
        print(f"Setting doorbell {cam_id} to ringtone id={new_ringtone_id}...")
        patch_camera_ringtone(sess, cam_id, new_ringtone_id)

    print("Rotation run completed.")


# =========================
# main
# =========================

def main():
    parser = argparse.ArgumentParser(
        description="Rotate UniFi Protect doorbell visitor tones by uploading random mp3 files."
    )
    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG_PATH),
        help=f"Path to config file (default: {DEFAULT_CONFIG_PATH})",
    )
    parser.add_argument(
        "--configure",
        action="store_true",
        help="Interactive configuration mode.",
    )

    args = parser.parse_args()
    config_path = Path(args.config)

    if args.configure:
        configure(config_path)
    else:
        run_rotation(config_path)


if __name__ == "__main__":
    main()
