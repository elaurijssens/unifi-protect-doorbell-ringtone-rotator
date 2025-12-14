#!/usr/bin/env python3
import argparse
import json
import os
import random
import sys
from pathlib import Path

import requests


# =========================
# Constants / defaults
# =========================

DEFAULT_CONFIG_PATH = Path.home() / ".unifi_tone_rotation.json"
ROTATION_SLOTS = ["rotation_a", "rotation_b"]
MAX_DOORBELL_RINGTONES = 10


# =========================
# Config helpers
# =========================

def load_config(path: Path) -> dict:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_config(cfg: dict, path: Path) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    print(f"Config saved to {path}")


# =========================
# Protect session login
# =========================

def login_protect_session(base_url: str) -> requests.Session:
    """
    Correct login flow for UNVR Pro / UniFi OS 4.4.3 / Protect 6.1.79.

    Auth happens at OS level (/api/auth/login), not under /proxy/protect.
    """
    import os, sys, requests

    username = os.getenv("UNVR_USER")
    password = os.getenv("UNVR_PASSWORD")

    if not username or not password:
        print("Error: UNVR_USER and UNVR_PASSWORD must be set.")
        sys.exit(1)

    sess = requests.Session()
    sess.verify = False  # self-signed certs

    login_url = f"{base_url}/api/auth/login"

    resp = sess.post(
        login_url,
        json={
            "username": username,
            "password": password,
            "token": "",
            "rememberMe": False,
        },
        headers={
            "Content-Type": "application/json",
            "Accept": "*/*",
            "Origin": base_url,
        },
    )

    if resp.status_code != 200:
        print(f"Login failed: HTTP {resp.status_code}")
        try:
            print(resp.json())
        except Exception:
            print(resp.text)
        sys.exit(1)

    # CSRF token is REQUIRED for Protect writes
    csrf = resp.headers.get("X-CSRF-Token") or resp.headers.get("x-csrf-token")
    if not csrf:
        print("Login succeeded but no CSRF token received.")
        sys.exit(1)

    sess.headers.update({
        "X-CSRF-Token": csrf,
        "Accept": "application/json",
    })

    return sess
# =========================
# Protect API helpers
# =========================

def get_cameras(sess: requests.Session, base_url: str):
    r = sess.get(f"{base_url}/proxy/protect/api/cameras")
    r.raise_for_status()
    return r.json()


def get_camera(sess: requests.Session, base_url: str, cam_id: str):
    r = sess.get(f"{base_url}/proxy/protect/api/cameras/{cam_id}")
    r.raise_for_status()
    return r.json()


def is_doorbell(cam: dict) -> bool:
    flags = cam.get("featureFlags") or {}
    if flags.get("isDoorbell"):
        return True
    model = (cam.get("model") or "").lower()
    name = (cam.get("name") or "").lower()
    return "doorbell" in model or "doorbell" in name


def get_ringtones(sess: requests.Session, base_url: str):
    r = sess.get(f"{base_url}/proxy/protect/api/files/ringtones")
    r.raise_for_status()
    return r.json()


def count_doorbell_ringtones(ringtones):
    return sum(
        1 for r in ringtones
        if "doorbell" in (r.get("metadata") or {}).get("supportedBy", [])
    )


def group_ringtones_by_original(ringtones):
    grouped = {}
    for r in ringtones:
        orig = r.get("originalName")
        if orig:
            grouped.setdefault(orig, []).append(r)
    return grouped


def delete_ringtone(sess, base_url, ringtone_id):
    r = sess.delete(
        f"{base_url}/proxy/protect/api/files/ringtones/{ringtone_id}",
        params={"ignoreFileExtension": "true"},
    )
    r.raise_for_status()


def upload_ringtone(sess, base_url, slot_name: str, mp3_path: Path):
    url = f"{base_url}/proxy/protect/api/files/ringtones"
    with mp3_path.open("rb") as f:
        files = {
            "file": (f"{slot_name}.mp3", f, "audio/mpeg"),
        }
        r = sess.post(url, files=files)
    r.raise_for_status()

    doorbell = None
    for item in r.json():
        if "doorbell" in (item.get("metadata") or {}).get("supportedBy", []):
            doorbell = item

    if not doorbell:
        raise RuntimeError("Upload succeeded but no doorbell ringtone returned")

    return doorbell


def patch_camera_ringtone(sess, base_url, cam_id, ringtone_id):
    cam = get_camera(sess, base_url, cam_id)

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

    payload["speakerSettings"]["ringtoneId"] = ringtone_id

    r = sess.patch(
        f"{base_url}/proxy/protect/api/cameras/{cam_id}",
        json=payload,
    )
    r.raise_for_status()


# =========================
# Configure mode
# =========================

def configure(cfg_path: Path):
    cfg = load_config(cfg_path)

    base_url = input(f"Base URL [{cfg.get('base_url', '')}]: ").strip() or cfg.get("base_url")
    ringtone_dir = input(f"MP3 directory [{cfg.get('ringtone_directory', '')}]: ").strip() or cfg.get("ringtone_directory")

    if not base_url or not ringtone_dir:
        print("Base URL and MP3 directory are required.")
        sys.exit(1)

    sess = login_protect_session(base_url)
    cams = get_cameras(sess, base_url)

    print("\nAvailable cameras:")
    for idx, cam in enumerate(cams):
        label = "[doorbell]" if is_doorbell(cam) else "[camera]"
        print(f"{idx}: {label} {cam.get('name')} ({cam.get('id')})")

    raw = input("\nSelect doorbells by index (comma-separated): ").strip()
    selected = []
    if raw:
        for part in raw.split(","):
            i = int(part.strip())
            selected.append(cams[i]["id"])

    cfg.update({
        "base_url": base_url,
        "ringtone_directory": ringtone_dir,
        "doorbell_ids": selected,
    })

    save_config(cfg, cfg_path)


# =========================
# Rotation logic
# =========================

def run(cfg_path: Path):
    cfg = load_config(cfg_path)
    if not cfg:
        print("Config not found. Run with --configure first.")
        sys.exit(1)

    base_url = cfg["base_url"]
    mp3_dir = Path(cfg["ringtone_directory"])
    doorbells = cfg.get("doorbell_ids", [])

    if not doorbells:
        print("No doorbells configured.")
        return

    mp3s = [p for p in mp3_dir.iterdir() if p.suffix.lower() == ".mp3"]
    if not mp3s:
        print("No MP3 files found.")
        sys.exit(1)

    sess = login_protect_session(base_url)
    ringtones = get_ringtones(sess, base_url)

    grouped = group_ringtones_by_original(ringtones)
    count = count_doorbell_ringtones(ringtones)

    slot = ROTATION_SLOTS[0]
    for s in ROTATION_SLOTS:
        if s not in grouped:
            slot = s
            break

    if count >= MAX_DOORBELL_RINGTONES and slot not in grouped:
        print("Error: doorbell ringtone limit reached.")
        sys.exit(1)

    if slot in grouped:
        delete_ringtone(sess, base_url, grouped[slot][0]["id"])

    chosen = random.choice(mp3s)
    print(f"Uploading {chosen.name} as {slot}")

    ringtone = upload_ringtone(sess, base_url, slot, chosen)

    for cam_id in doorbells:
        print(f"Setting doorbell {cam_id} → {slot}")
        patch_camera_ringtone(sess, base_url, cam_id, ringtone["id"])

    print("Rotation complete.")


# =========================
# main
# =========================

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--configure", action="store_true")
    p.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    args = p.parse_args()

    cfg_path = Path(args.config)

    if args.configure:
        configure(cfg_path)
    else:
        run(cfg_path)


if __name__ == "__main__":
    main()
