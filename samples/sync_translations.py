#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Synchronizes 'translation.json' with 'translation-sample.txt'.

Expected structure:
    project/
    ├── translation.json
    └── samples/
        ├── sync_translations.py
        └── translation-sample.txt

Features:
    - Adds missing strings (using English as fallback)
    - Removes obsolete strings
    - Preserves existing translations
    - Sorts alphabetically
    - Creates backup 'translation.json.bak'
    - --check mode (verification only)

--check mode (verify only):
    python sync_translations.py --check

    Example output:
        Language: pt_BR
            +3 added
            -1 removed
        Language: fr
            OK
        Language: es
            +2 added

Normal usage:
    python sync_translations.py

    Creates 'translation.json.bak' and updates 'translation.json'.

Exit codes:
    0 - Success
    1 - Error or differences found in --check mode
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import shutil
import sys

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent

SAMPLE_FILE = SCRIPT_DIR / "translation-sample.txt"
TRANSLATION_FILE = SCRIPT_DIR.parent / "translation.json"
BACKUP_FILE = SCRIPT_DIR.parent / "translation.json.bak"


def load_json(path: pathlib.Path):

    text = path.read_text(encoding="utf-8")

    match = re.search(r'(?m)^[ \t]*([\[{])', text)

    if match is None:
        raise ValueError(f"No JSON found in {path}")

    return json.loads(text[match.start(1):])


def ordered_translation(data: dict) -> dict:
    return dict(sorted(data.items(), key=lambda item: item[0].casefold()))


def main() -> int:

    parser = argparse.ArgumentParser(
        description="Synchronize translation.json with translation-sample.txt"
    )

    parser.add_argument(
        "--check",
        action="store_true",
        help="Only report differences without modifying files."
    )

    args = parser.parse_args()

    if not SAMPLE_FILE.exists():
        print(f"ERROR: {SAMPLE_FILE} not found.", file=sys.stderr)
        return 1

    if not TRANSLATION_FILE.exists():
        print(f"ERROR: {TRANSLATION_FILE} not found.", file=sys.stderr)
        return 1

    print(f"Reading {SAMPLE_FILE.name}...")
    sample = load_json(SAMPLE_FILE)

    print(f"Reading {TRANSLATION_FILE.name}...")
    translations_data = load_json(TRANSLATION_FILE)
    
    # Extract the language list
    if "language" in translations_data:
        translations = translations_data["language"]
    else:
        # Fallback: if it's already a list at root level
        translations = translations_data

    english = sample["translation"]
    english_keys = set(english.keys())

    total_languages = 0
    has_changes = False

    for language in translations:

        if not isinstance(language, dict):
            print(f"Warning: Skipping non-dictionary item: {language}")
            continue

        total_languages += 1

        code = language.get("code", "unknown")
        current = language.get("translation", {})

        current_keys = set(current.keys())

        missing = sorted(english_keys - current_keys, key=str.casefold)
        obsolete = sorted(current_keys - english_keys, key=str.casefold)

        print(f"\nLanguage: {code}")

        if missing:
            print(f"    +{len(missing)} added")

        if obsolete:
            print(f"    -{len(obsolete)} removed")

        if not missing and not obsolete:
            print("    OK")

        if missing or obsolete:
            has_changes = True

        if args.check:
            continue

        new_translation = {}

        for key in english:

            if key in current:
                new_translation[key] = current[key]
            else:
                new_translation[key] = english[key]

        language["translation"] = ordered_translation(new_translation)

    print(f"\nProcessed {total_languages} languages.")

    if args.check:

        if has_changes:
            print("\nDifferences found.")
            return 1

        print("\nEverything is synchronized.")
        return 0

    if not has_changes:
        print("\nNothing to do.")
        return 0

    print(f"\nCreating backup: {BACKUP_FILE.name}")
    shutil.copy2(TRANSLATION_FILE, BACKUP_FILE)

    print(f"Writing {TRANSLATION_FILE.name}...")

    with TRANSLATION_FILE.open("w", encoding="utf-8") as fp:

        json.dump(
            translations_data,  # Save the entire structure, not just the list
            fp,
            indent=2,
            ensure_ascii=False
        )

        fp.write("\n")

    print("Done.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
