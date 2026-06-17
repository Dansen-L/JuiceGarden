#!/usr/bin/env python3
"""
flag-init — one-shot container
Mints exactly 23 unique JG{hex32} flag values and writes flags.json to /flag-data.
"""
import os
import json
import secrets

OUTPUT_PATH = "/flag-data/flags.json"

# All 23 challenge codes in deterministic order
CHALLENGE_CODES = [
    "auth01", "auth02", "auth03", "auth04",
    "inj01",  "inj02",  "inj03",  "inj04",
    "bac01",  "bac02",  "bac03",  "bac04",
    "cs01",   "cs02",   "cs03",
    "ss01",   "ss02",   "ss03",
    "bl01",   "bl02",   "bl03",
    "mission_alpha",
    "bonus",
]

assert len(CHALLENGE_CODES) == 23, f"Expected 23 codes, got {len(CHALLENGE_CODES)}"


def mint_flag():
    """Generate one JG{hex32} flag."""
    return "JG{" + secrets.token_hex(16) + "}"


def main():
    flags = {}
    used = set()
    for code in CHALLENGE_CODES:
        flag = mint_flag()
        # Ensure uniqueness (astronomically unlikely collision, but be correct)
        while flag in used:
            flag = mint_flag()
        flags[code] = flag
        used.add(flag)

    os.makedirs("/flag-data", exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(flags, f, indent=2)

    print(f"[flag-init] Generated {len(flags)} flags → {OUTPUT_PATH}")
    for code, flag in flags.items():
        print(f"  {code}: {flag}")


if __name__ == "__main__":
    main()
