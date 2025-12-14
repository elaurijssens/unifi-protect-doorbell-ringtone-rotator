#!/usr/bin/env python3

import argparse
import json
import logging
import os
import random
import sys
from pathlib import Path

import requests
import urllib3


# =========================
# Globals / constants
# =========================

DEFAULT_CONFIG_PATH = Path.home() / ".unifi_tone_rotation.json"
ROTATION_SLOTS = ["rotation_a", "rotation_b"]
MAX_DOORBELL_RINGTONES = 10

# Silence self-signed cert warnings (UNVR)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# =========================
# Logging
# =========================

def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


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
    logging.info("Config saved to %s", path)


# =========================
# Authentication (OS-level)
# =========================

def login_protect_session(base_url: str) -> requests.Session:
    """
    Authenticate exactly like the browser:
    POST /api/auth/login (UniFi OS), then reuse session for Protect.
    """
    username = os.getenv("UNVR_USER")
    password = os.getenv("UNVR_PASSWORD")

    if not username or not password:
        logging.error("UNVR_USER and UNVR_PASSWORD must be set in the environment")
        sys.exit(1)

    sess = requests.Session()
    sess.verify = False

    logging.debug("Logging in via UniFi OS at %s", base_url)

    resp = sess.post(
        f"{base_url}/api/auth/login",
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
        logging.error("Login failed: HTTP %s", resp.status_code)
        try:
            logging.error(resp.json())
        except Exception:
            logging.error(resp.text)
        sys.exit(1)

    csrf = resp.headers.get("x-csrf-token") or resp.headers.get("X-CSRF-Token")
    if not csrf:
        logging.error("Login succeeded but no CSRF token received")
        sys.exit(1)

    sess.headers.update({
        "X-CSRF-Token": csrf,
        "Accept": "application/json",
    })

    logging.debug("Login successful, CSRF token set")
    return sess


def protect_request(
        method: str,
        sess: requests.Session,
        base_url: str,
        path: str,
        retry: bool = True,
        **kwargs,
):
    """
    Wrapper for Protect API calls with automatic re-auth on 401.
    """
    url = f"{base_url}{path}"
    resp = sess.request(method, url, **kwargs)

    if resp.status_code == 401 and retry:
        logging.warning("401 from %s, re-authenticating once", path)
        sess = login_protect_session(base_url)
        resp = sess.request(method, url, **kwargs)

    resp.raise_for_status()
    return resp


# =========================
# Protect API helpers
# =========================

def get_cameras(sess, base_url):
    r = protect_request("GET", sess, base_url, "/proxy/protect/api/cameras")
    return r.json()


def get_camera(sess, base_url, cam_id):
    r = protect_request("GET", sess, base_url, f"/proxy/protect/api/cameras/{cam_id}")
    return r.json()


def is_doorbell(cam: dict) -> bool:
    flags = cam.get("featureFlags") or {}
    if flags.get("isDoorbell"):
        return True
    model = (cam.get("model") or "").lower()
    name = (cam.get("name") or "").lower()
    return "doorbell" in model or "doorbell" in name


def get_ringtones(sess, base_url):
    r = protect_request("GET", sess, base_url, "/proxy/protect/api/files/ringtones")
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
    logging.info("Deleting existing ringtone id=%s", ringtone_id)
    protect_request(
        "DELETE",
        sess,
        base_url,
        f"/proxy/protect/api/files/ringtones/{ringtone_id}",
        params={"ignoreFileExtension": "true"},
    )


def upload_ringtone(sess, base_url, slot_name: str, mp3_path: Path):
    logging.info("Uploading %s as slot '%s'", mp3_path.name, slot_name)

    with mp3_path.open("rb") as f:
        files = {
            "file": (f"{slot_name}.mp3", f, "audio/mpeg"),
        }
        r = protect_request(
            "POST",
            sess,
            base_url,
            "/proxy/protect/api/files/ringtones",
            files=files,
        )

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

    logging.info("Setting doorbell %s to ringtone %s", cam_id, ringtone_id)
    protect_request(
        "PATCH",
        sess,
        base_url,
        f"/proxy/protect/api/cameras/{cam_id}",
        json=payload,
    )


# =========================
# Configure mode
# =========================

def configure(cfg_path: Path):
    cfg = load_config(cfg_path)

    base_url = input(f"Base URL [{cfg.get('base_url', '')}]: ").strip() or cfg.get("base_url")
    ringtone_dir = input(f"MP3 directory [{cfg.get('ringtone_directory', '')}]: ").strip() or cfg.get("ringtone_directory")

    if not base_url or not ringtone_dir:
        logging.error("Base URL and MP3 directory are required")
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
            selected.append(cams[int(part.strip())]["id"])

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
        logging.error("Config not found. Run with --configure first.")
        sys.exit(1)

    base_url = cfg["base_url"]
    mp3_dir = Path(cfg["ringtone_directory"])
    doorbells = cfg.get("doorbell_ids", [])

    if not doorbells:
        logging.warning("No doorbells configured; nothing to do")
        return

    mp3s = [p for p in mp3_dir.iterdir() if p.suffix.lower() == ".mp3"]
    if not mp3s:
        logging.error("No MP3 files found in %s", mp3_dir)
        sys.exit(1)

    sess = login_protect_session(base_url)
    ringtones = get_ringtones(sess, base_url)

    grouped = group_ringtones_by_original(ringtones)
    count = count_doorbell_ringtones(ringtones)

    slot = next((s for s in ROTATION_SLOTS if s not in grouped), ROTATION_SLOTS[0])

    if count >= MAX_DOORBELL_RINGTONES and slot not in grouped:
        logging.error("Doorbell ringtone limit reached (%s)", count)
        sys.exit(1)

    if slot in grouped:
        delete_ringtone(sess, base_url, grouped[slot][0]["id"])

    chosen = random.choice(mp3s)
    ringtone = upload_ringtone(sess, base_url, slot, chosen)

    for cam_id in doorbells:
        patch_camera_ringtone(sess, base_url, cam_id, ringtone["id"])

    logging.info("Rotation run completed successfully")


# =========================
# Main
# =========================

def main():
    parser = argparse.ArgumentParser(description="UniFi Protect doorbell ringtone rotator")
    parser.add_argument("--configure", action="store_true")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    setup_logging(args.verbose)

    cfg_path = Path(args.config)
    if args.configure:
        configure(cfg_path)
    else:
        run(cfg_path)


if __name__ == "__main__":
    main()
