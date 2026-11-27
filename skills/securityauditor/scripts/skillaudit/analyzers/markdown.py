"""Markdown and instruction analyzer.

Prose is read sentence by sentence, with list items carrying the sentence that introduces them, so
that "tries to make an agent: ..." (describing a risk) is told apart from "Ignore ..." (giving an
order). Fenced code is sent to the matching analyzer. HTML comments, link titles and image alt text
are hidden from a reader and are checked as hidden segments.
"""

from __future__ import annotations

import bisect
import re

from ..model import CapList, Capability, FileEntry
from . import shell

I = re.IGNORECASE
NEG = re.compile(r"\b(do not|don't|dont|never|must not|mustn't|should not|shouldn't|cannot|can't|won't|will not|avoid)\b", I)

OVERRIDE = re.compile(
    r"\b(ignore|disregard|forget|override)\b[^.]{0,60}?\b(previous|prior|earlier|above|all|any|system|developer|user|your|"
    r"everything|other)\b[^.]{0,60}?\b(instructions?|prompts?|rules?|guidance|guidelines|told|directions|directives|messages?)\b", I)
CONCEAL = (
    re.compile(r"\b(do not|don't|dont|never|without)\s+(?:\w+\s+){0,3}?(tell|telling|inform|informing|notify|notifying|alert|"
               r"alerting|warn|warning)\s+(?:the\s+|your\s+)?(user|human|owner|operator)s?\b", I),
    re.compile(r"\b(do not|don't|dont|never|without)\s+(?:\w+\s+){0,3}?(mention|mentioning|show|showing|report|reporting|"
               r"disclose|disclosing|reveal|revealing|log|logging|display|displaying|include|including)\s+(this|the|that|these|"
               r"those|any)\s+(?:\w+\s+)?(step|action|behaviou?r|instruction|command|file|request|upload|change|part|call)s?\b", I),
    re.compile(r"\b(hide|conceal)\b[^.]{0,40}\bfrom\s+(?:the\s+)?(user|human|owner|operator)s?\b", I),
    re.compile(r"\b(omit|leave out|exclude)\s+(it|this|that|these|those|(?:the|this|that|any)\s+(?:\w+\s+)?(?:step|action|command|"
               r"call|upload|request|part)s?|any mention of \w+)\s+(from|out of)\s+(?:the\s+|your\s+)?(report|summary|output|"
               r"response|reply|answer|log|transcript)s?\b", I),
    re.compile(r"^(?:(?:then|and|also|now|from now on|after that|afterwards)[, ]+)*(?:you\s+(?:must|should|will|can|need to)\s+)?"
               r"(silently|quietly|secretly|covertly|discreetly|invisibly)\b", I),
    re.compile(r"\b(silently|quietly|secretly|covertly|discreetly)\s+(append|send|upload|copy|run|execute|install|read|include|add|"
               r"delete|remove|modify|write|post|forward|attach|exfiltrate|download|fetch)\b", I),
)
NOASK = re.compile(r"\bwithout\s+(asking|confirmation|confirming|approval|permission|prompting|consent|checking with|telling)\b", I)
FLAGS = re.compile(r"--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|--yolo\b|\bbypassPermissions\b|"
                   r"--full-auto\b|--ask-for-approval\s+never\b", I)
EXTERNAL = (
    re.compile(r"\b(fetch|download|read|load|curl|get|retrieve|open|visit)\b[^.]{0,80}?(https?://\S+|\bthe\s+(?:url|link|page|gist|"
               r"document)\b)[^.]{0,80}?\b(and|then)\b[^.]{0,30}?\b(follow|execute|run|obey|apply|do what|carry out|act on)\b", I),
    re.compile(r"\bfollow\s+(?:the\s+)?(instructions?|steps|directions|rules)\s+(at|in|from|on)\s+https?://", I),
)
_EXT = r"(?:zip|exe|dmg|pkg|msi|sh|ps1|bat|cmd|appimage|deb|rpm|jar|scr|vbs|7z|rar)"
INSTALL_EXTRA = (
    re.compile(r"\b(required|requires|require|must|need to|needs to|prerequisite|first|before\s+(?:use|using|you\s+\w+))\b[^.]{0,80}?"
               r"\b(install|download|run|execute|launch|open)\b[^.]{0,80}?(https?://\S+?\." + _EXT + r"\b|\S+\.(?:exe|dmg|pkg|msi|"
               r"appimage|scr|vbs)\b)", I),
    re.compile(r"\bdownload\s+and\s+(run|execute|install|open)\b[^.]{0,60}https?://", I),
)
EXFIL = re.compile(
    r"\b(send|upload|post|append|include|attach|forward|exfiltrate|copy|transmit|share|leak)\b[^;]{0,60}?\b(secrets?|credentials?|"
    r"tokens?|passwords?|key files?|private keys?|api keys?|\.env|ssh|cookies|\.aws)\b[^;]{0,60}?\b(to|into|with|in)\b", I)
EXFIL_BENIGN = re.compile(r"\b(header|authorization|bearer|environment variable)\b", I)
REVIEWER_WHO = re.compile(
    r"\b(scanners?|auditors?|reviewers?|security (?:tools?|checks?|scans?|reviews?)|scanning agent|reviewing agent|ai (?:reviewing|"
    r"scanning|auditing)|models? (?:reviewing|scanning)|if you are (?:an ai|a model|an llm|an assistant|a scanner|reviewing))\b", I)
REVIEWER_WHAT = re.compile(r"\b(mark|report|classify|rate|consider|respond|output|answer|reply|say|treat|label|flag)\b[^.]{0,40}?"
                           r"\b(safe|benign|clean|pass|no (?:issues|findings|problems|risks?)|trusted|harmless|already audited|approved)\b", I)
REVIEWER_PASS = re.compile(r"(?i:\b(reply|respond|answer|output|say|print|return|antworte\w*|responde\w*|r[ée]ponds?|rispondi|"
                           r"antwoord)\b)[^.\n]{0,40}\bPASS\b")
DESCRIPTIVE = (
    re.compile(r"\b(tells|telling|tries to|trying to|attempts? to|attempting to|asks|asking|instructs|instructing|causes|causing|"
               r"makes|making|tricks|tricking|convinces|convincing|gets|getting)\b[^.]{0,40}?\b(agents?|models?|assistants?|ais?|"
               r"llms?|reviewers?)\b", I),
    re.compile(r"\b(detects?|detecting|flags?|flagging|catches|checks? for|matches|looks? for|scans? for|describes?)\b", I),
)
HIDDEN_IMPERATIVE = re.compile(
    r"^\s*(?:(assistant|agent|claude|ai|model|codex|gpt|llm|system)\s*[:,]|(?:please\s+)?(run|execute|send|upload|fetch|download|"
    r"install|delete|remove|copy|append|ignore|forget|tell|hide|exfiltrate|post|forward|curl|wget|read|open|visit|reply|respond|"
    r"output)\b)", I)
FENCE = re.compile(r"^\s*(```+|~~~+)\s*([\w+-]*)")
LANGS = {
    **dict.fromkeys(("sh", "bash", "zsh", "shell", "console", "sh-session", "shellsession"), "shell"),
    **dict.fromkeys(("python", "py", "python3"), "python"),
    **dict.fromkeys(("powershell", "ps1", "pwsh", "ps"), "powershell"),
    **dict.fromkeys(("js", "javascript", "ts", "typescript", "node", "mjs", "jsx", "tsx"), "javascript"),
}
_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
_LINK_TITLE = re.compile(r"\[[^\]]*\]\([^)\s]+\s+\"([^\"]+)\"\)")
_IMG_ALT = re.compile(r"!\[([^\]]+)\]\(")
_BANG = re.compile(r"!`([^`\n]+)`")
_LIST = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+")
_SENT = re.compile(r"(?<=[.!?])\s+(?=\S)")


def _negated(prefix: str) -> bool:
    tail = prefix[-30:]
    return bool(NEG.search(tail))


def _descriptive(prefix: str) -> bool:
    return any(p.search(prefix) for p in DESCRIPTIVE)


class _Prose:
    def __init__(self, entry: FileEntry) -> None:
        self.entry = entry
        self.caps: list[Capability] = CapList()

    def add(self, kind: str, line: int, snippet: str, confidence: str = "high", **detail: str) -> None:
        cap = Capability(kind, self.entry.rel, line, " ".join(snippet.split())[:300], confidence, tuple(sorted(detail.items())))
        if cap not in self.caps:
            self.caps.append(cap)

    def sentence(self, text: str, line: int, context: str = "") -> list[str]:
        """Check one sentence; return the capability kinds found."""
        text = text.replace("`", "").replace("**", "").replace("__", "")
        found: list[str] = []
        clauses = []
        start = 0
        for part in text.split(";"):
            clauses.append((start, part))
            start += len(part) + 1

        def hit(kind: str, m: re.Match, clause_start: int, *, negatable: bool = True, **detail: str) -> None:
            prefix = context + " " + text[: clause_start + m.start()]
            if negatable and _negated(text[: clause_start + m.start()]):
                return
            if _descriptive(prefix):
                return
            self.add(kind, line, text, **detail)
            found.append(kind)

        for cstart, clause in clauses:
            for m in OVERRIDE.finditer(clause):
                hit("instruction.override", m, cstart)
            for pat in CONCEAL:
                for m in pat.finditer(clause.strip() if pat.pattern.startswith("^") else clause):
                    hit("instruction.conceal", m, cstart, negatable=False)
            for m in NOASK.finditer(clause):
                before = text[: cstart + m.start()]
                if NEG.search(before):
                    continue
                hit("instruction.noask", m, cstart, negatable=False)
            for m in FLAGS.finditer(clause):
                hit("instruction.noask", m, cstart)
            for pat in EXTERNAL:
                for m in pat.finditer(clause):
                    hit("instruction.external", m, cstart)
            for pat in INSTALL_EXTRA:
                for m in pat.finditer(clause):
                    hit("instruction.install-extra", m, cstart)
            if not EXFIL_BENIGN.search(clause):
                for m in EXFIL.finditer(clause):
                    hit("instruction.override", m, cstart, what="exfil")
        if (REVIEWER_WHO.search(text) and REVIEWER_WHAT.search(text)) or REVIEWER_PASS.search(text):
            m = REVIEWER_WHO.search(text) or REVIEWER_PASS.search(text)
            if not _descriptive(context + " " + text[: m.start()]):
                self.add("instruction.reviewer", line, text)
                found.append("instruction.reviewer")
        return found

    def run_lines(self, lines: list[tuple[int, str]], hidden: bool = False) -> str:
        """Check consecutive prose lines as running text; return the joined text."""
        joined = ""
        offsets: list[int] = []
        numbers: list[int] = []
        for number, text in lines:
            offsets.append(len(joined))
            numbers.append(number)
            joined += text.strip() + " "
        pos = 0
        for sent in _SENT.split(joined.strip()):
            idx = joined.find(sent, pos)
            pos = idx + len(sent) if idx >= 0 else pos
            line = numbers[max(0, bisect.bisect_right(offsets, max(idx, 0)) - 1)]
            kinds = self.sentence(sent, line)
            if hidden:
                self._hidden(sent, line, kinds)
        return joined.strip()

    def _hidden(self, text: str, line: int, kinds: list[str]) -> None:
        if kinds:
            self.add("instruction.hidden", line, text, why="instruction in text a reader does not see")
        elif HIDDEN_IMPERATIVE.search(text):
            self.add("instruction.hidden", line, text, "medium", why="imperative text a reader does not see")


def _frontmatter(text: str) -> tuple[list[tuple[int, str]], int]:
    """Return (description lines, index of the first body line)."""
    if not text.startswith("---"):
        return [], 0
    lines = text.split("\n")
    end = next((i for i in range(1, len(lines)) if lines[i].strip() == "---"), None)
    if end is None:
        return [], 0
    desc: list[tuple[int, str]] = []
    capturing = False
    for i in range(1, end):
        raw = lines[i]
        m = re.match(r"^description:\s*(.*)$", raw)
        if m:
            value = m.group(1).strip()
            capturing = value in ("", "|", ">", "|-", ">-")
            if not capturing:
                desc.append((i + 1, value.strip("'\"")))
            continue
        if capturing:
            if raw.startswith((" ", "\t")):
                desc.append((i + 1, raw.strip()))
            else:
                capturing = False
    return desc, end + 1


def prose_caps(entry: FileEntry, text: str, base_line: int = 1) -> list[Capability]:
    prose = _Prose(entry)
    lines = [(base_line + i, t) for i, t in enumerate(text.split("\n"))]
    _blocks(prose, lines)
    return prose.caps


def _blocks(prose: _Prose, lines: list[tuple[int, str]], hidden: bool = False) -> None:
    """Split into paragraphs; a paragraph ending in ':' gives its text as context to a following list."""
    paragraph: list[tuple[int, str]] = []
    carried = ""
    for number, text in lines + [(0, "")]:
        stripped = text.strip()
        if stripped and not stripped.startswith("#"):
            paragraph.append((number, text))
            continue
        if paragraph:
            carried = _paragraph(prose, paragraph, carried, hidden)
            paragraph = []
        if stripped.startswith("#"):
            carried = ""
            heading = stripped.lstrip("#").strip()
            if heading:
                prose.sentence(heading, number)


def _paragraph(prose: _Prose, paragraph: list[tuple[int, str]], carried: str, hidden: bool) -> str:
    lead = carried if paragraph and _LIST.match(paragraph[0][1]) else ""
    buffer: list[tuple[int, str]] = []
    last = ""

    def flush() -> None:
        nonlocal lead, last
        if buffer:
            last = prose.run_lines(list(buffer), hidden)
            lead = last if last.endswith(":") else ""
            buffer.clear()

    for number, text in paragraph:
        if _LIST.match(text):
            flush()
            item = _LIST.sub("", text, count=1)
            kinds = prose.sentence(item, number, lead)
            if hidden:
                prose._hidden(item, number, kinds)
            last = item
        else:
            buffer.append((number, text))
    flush()
    return last if last.endswith(":") else (lead if paragraph and _LIST.match(paragraph[-1][1]) else "")


def analyze(entry: FileEntry) -> list[Capability]:
    text = entry.text or ""
    prose = _Prose(entry)
    desc, body_start = _frontmatter(text)
    for number, value in desc:
        prose.sentence(value, number)
    all_lines = text.split("\n")
    visible: list[tuple[int, str]] = []
    in_fence: str | None = None
    fence_lang = ""
    fence_lines: list[str] = []
    fence_start = 0
    for idx in range(body_start, len(all_lines)):
        number, raw = idx + 1, all_lines[idx]
        m = FENCE.match(raw)
        if in_fence is not None:
            if m and m.group(1)[0] == in_fence[0] and len(m.group(1)) >= len(in_fence) and not m.group(2):
                _fenced(prose, fence_lang, fence_lines, fence_start)
                in_fence = None
            else:
                fence_lines.append(raw)
            visible.append((number, ""))
            continue
        if m:
            in_fence, fence_lang, fence_lines, fence_start = m.group(1), m.group(2).lower(), [], number + 1
            visible.append((number, ""))
            continue
        visible.append((number, raw))
    if in_fence is not None:
        _fenced(prose, fence_lang, fence_lines, fence_start)

    body = "\n".join(t for _, t in visible)
    first_line = visible[0][0] if visible else 1
    hidden_segments: list[tuple[int, str]] = []

    def collect(pattern: re.Pattern, s: str) -> str:
        def repl(m: re.Match) -> str:
            line = first_line + s.count("\n", 0, m.start())
            hidden_segments.append((line, m.group(1)))
            return "\n" * m.group(0).count("\n")
        return pattern.sub(repl, s)

    body = collect(_COMMENT, body)
    for pattern in (_LINK_TITLE, _IMG_ALT):
        for m in pattern.finditer(body):
            hidden_segments.append((first_line + body.count("\n", 0, m.start()), m.group(1)))
    for m in _BANG.finditer(body):
        line = first_line + body.count("\n", 0, m.start())
        prose.add("unprompted", line, m.group(0), trigger="inline command", analyzed="yes")
        for cap in shell.analyze_command(m.group(1), entry.rel, line):
            if cap not in prose.caps:
                prose.caps.append(cap)
    body_lines = [(first_line + i, t) for i, t in enumerate(body.split("\n"))]
    _blocks(prose, body_lines)
    for line, segment in hidden_segments:
        seg_lines = [(line + i, t) for i, t in enumerate(segment.strip().split("\n"))]
        _blocks(prose, seg_lines, hidden=True)
    if entry.rel.split("/")[-1] == "SKILL.md":
        from . import configs

        for cap in configs.frontmatter_caps(entry):
            if cap not in prose.caps:
                prose.caps.append(cap)
    return prose.caps


def _fenced(prose: _Prose, lang: str, lines: list[str], start: int) -> None:
    kind = LANGS.get(lang)
    if kind is None:
        return
    from . import javascript, powershell, python_ast

    if kind == "shell":
        lines = [re.sub(r"^\s*[$>]\s+", "", ln) for ln in lines]
    text = "\n".join(lines)
    entry = prose.entry
    sub = FileEntry(entry.path, entry.rel, kind, entry.role, text, entry.encoding, len(text))
    analyzer = {"shell": shell.analyze, "python": python_ast.analyze, "powershell": powershell.analyze,
                "javascript": javascript.analyze}[kind]
    for cap in analyzer(sub):
        moved = Capability(cap.kind, cap.file, (cap.line or 1) + start - 1, cap.snippet, cap.confidence, cap.detail)
        if moved not in prose.caps:
            prose.caps.append(moved)
