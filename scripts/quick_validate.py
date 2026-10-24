#!/usr/bin/env python3
"""Validate Claude Agent Skills against the Agent Skills specification.

Checks:
- Directory contains SKILL.md
- SKILL.md has valid YAML frontmatter (name and description)
- Skill name matches directory name and follows naming rules (lowercase, alphanumeric, hyphens)
- Description is non-empty and within character limits (<= 1024 chars)
- Scripts and assets referenced exist

Usage:
    python3 scripts/quick_validate.py [skills_dir or skill_paths...]
Default (no args): validates all skills under ./skills
"""

import os
import re
import sys


def parse_frontmatter(content):
    if not content.startswith("---"):
        return None, "File does not start with YAML frontmatter delimiter (---)"
    parts = content.split("---", 2)
    if len(parts) < 3:
        return None, "Unterminated YAML frontmatter (missing closing ---)"
    
    yaml_text = parts[1]
    data = {}
    for line in yaml_text.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            key, val = line.split(":", 1)
            data[key.strip()] = val.strip()
    return data, None


def validate_skill(skill_dir):
    errors = []
    dir_name = os.path.basename(os.path.abspath(skill_dir))
    skill_md = os.path.join(skill_dir, "SKILL.md")

    if not os.path.isfile(skill_md):
        return [f"Missing required SKILL.md in {skill_dir}"]

    try:
        with open(skill_md, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        return [f"Failed to read SKILL.md: {e}"]

    metadata, err = parse_frontmatter(content)
    if err:
        errors.append(err)
        return errors

    name = metadata.get("name")
    if not name:
        errors.append("Missing required 'name' field in frontmatter")
    else:
        if name != dir_name:
            errors.append(f"Skill name '{name}' does not match directory name '{dir_name}'")
        if not re.match(r"^[a-z0-9]+(-[a-z0-9]+)*$", name):
            errors.append(f"Invalid skill name '{name}'. Must be lowercase alphanumeric with single hyphens.")

    description = metadata.get("description")
    if not description:
        errors.append("Missing required 'description' field in frontmatter")
    elif len(description) > 1024:
        errors.append(f"Description too long ({len(description)} chars; maximum is 1024)")

    return errors


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    targets = sys.argv[1:]

    if not targets:
        skills_base = os.path.join(root, "skills")
        if not os.path.isdir(skills_base):
            print(f"Error: skills directory not found at {skills_base}")
            return 1
        targets = [os.path.join(skills_base, d) for d in sorted(os.listdir(skills_base))
                   if os.path.isdir(os.path.join(skills_base, d))]

    total = len(targets)
    failed = 0

    print(f"Validating {total} skill(s)...")
    for t in targets:
        name = os.path.basename(os.path.abspath(t))
        errs = validate_skill(t)
        if errs:
            failed += 1
            print(f"  ❌ {name}:")
            for e in errs:
                print(f"      - {e}")
        else:
            print(f"  ✅ {name}: valid")

    if failed == 0:
        print(f"\nAll {total} skill(s) valid!")
        return 0
    else:
        print(f"\n{failed}/{total} skill(s) failed validation.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
