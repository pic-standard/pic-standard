"""Regression: docs/ERRORS.md heading set must match PICErrorCode.

If a new PICErrorCode member is added, docs/ERRORS.md must gain a
matching level-3 heading under ## Error codes. If a member is renamed
or removed, the heading must move with it.
"""

from __future__ import annotations

import re
from pathlib import Path

from pic_standard.errors import PICErrorCode

REPO_ROOT = Path(__file__).resolve().parent.parent
ERRORS_MD = REPO_ROOT / "docs" / "ERRORS.md"


def _extract_error_code_headings() -> list[str]:
    """Return the H3 heading text values under the ## Error codes section.

    Reads docs/ERRORS.md, scans forward to the '## Error codes' anchor,
    then collects '### `PIC_XXX`' headings until the next '## ' heading
    or EOF. The backtick-wrapped code value is returned per heading.
    """
    text = ERRORS_MD.read_text(encoding="utf-8")

    in_error_codes = False
    codes: list[str] = []
    for line in text.splitlines():
        if line.startswith("## Error codes"):
            in_error_codes = True
            continue
        if in_error_codes and line.startswith("## "):
            # Next H2 section; end of Error codes region.
            break
        if not in_error_codes:
            continue
        m = re.match(r"^###\s+`(PIC_[A-Z0-9_]+)`\s*$", line)
        if m:
            codes.append(m.group(1))
    return codes


def test_errors_md_h3_set_matches_pic_error_code_enum() -> None:
    """Every PICErrorCode value has a matching H3 heading, and vice versa."""
    documented = set(_extract_error_code_headings())
    enum_values = {m.value for m in PICErrorCode}

    missing_in_doc = enum_values - documented
    extra_in_doc = documented - enum_values

    assert not missing_in_doc, (
        f"docs/ERRORS.md is missing headings for PICErrorCode members: {sorted(missing_in_doc)}"
    )
    assert not extra_in_doc, (
        f"docs/ERRORS.md has H3 headings that are NOT PICErrorCode members: {sorted(extra_in_doc)}"
    )


def test_errors_md_h3_count_matches_enum_length() -> None:
    """Backstop count check independent of set equality."""
    headings = _extract_error_code_headings()
    assert len(headings) == len(PICErrorCode), (
        f"docs/ERRORS.md has {len(headings)} H3 headings under '## Error "
        f"codes' but PICErrorCode has {len(PICErrorCode)} members. Update "
        f"the doc when adding/removing enum members."
    )
