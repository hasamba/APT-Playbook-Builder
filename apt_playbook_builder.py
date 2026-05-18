#!/usr/bin/env python3
"""
APT Playbook Builder

Lists MITRE ATT&CK groups, lets an analyst choose one, and asks an AI API to
produce a forensic investigation playbook based on the selected group's page.
"""

from __future__ import annotations

import argparse
import getpass
import html
import json
import os
import re
import sys
from datetime import date
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Iterable


GROUPS_URL = "https://attack.mitre.org/groups/"
DEFAULT_API_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_MODEL = "openrouter/auto"
DEFAULT_MAX_TOKENS = 6000
USER_AGENT = "APT-Playbook-Builder/1.0 (+https://attack.mitre.org/groups/)"
OPENROUTER_TITLE = "APT Playbook Builder"


@dataclass(frozen=True)
class Group:
    id: str
    name: str
    url: str
    aliases: str = ""
    description: str = ""


@dataclass(frozen=True)
class ReferenceSource:
    url: str
    title: str
    text: str


@dataclass(frozen=True)
class GroupPage:
    group: Group
    title: str
    summary: str
    sections: dict[str, str]
    techniques: list[str]
    software: list[str]
    reference_sources: list[ReferenceSource]


class MitreGroupsParser(HTMLParser):
    """Extracts group rows from the MITRE ATT&CK groups index."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.anchors: list[tuple[str, str]] = []
        self._current_href: str | None = None
        self._current_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "a":
            return
        href = dict(attrs).get("href")
        if href and re.fullmatch(r"/groups/G\d+/?", href):
            self._current_href = href
            self._current_text = []

    def handle_data(self, data: str) -> None:
        if self._current_href is not None:
            self._current_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag != "a" or self._current_href is None:
            return

        text = clean_text(" ".join(self._current_text))
        href = self._current_href
        self._current_href = None
        self._current_text = []

        if text:
            self.anchors.append((href, text))


class PageTextParser(HTMLParser):
    """Converts the useful visible content of a MITRE page into simple lines."""

    BLOCK_TAGS = {
        "address",
        "article",
        "aside",
        "blockquote",
        "br",
        "caption",
        "div",
        "footer",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "header",
        "li",
        "main",
        "p",
        "section",
        "td",
        "th",
        "tr",
    }

    SKIP_TAGS = {"script", "style", "noscript", "svg"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.lines: list[str] = []
        self._buffer: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self.SKIP_TAGS:
            self._skip_depth += 1
            return
        if self._skip_depth == 0 and tag in self.BLOCK_TAGS:
            self._flush()

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        text = clean_text(data)
        if text:
            self._buffer.append(text)

    def handle_endtag(self, tag: str) -> None:
        if tag in self.SKIP_TAGS and self._skip_depth:
            self._skip_depth -= 1
            return
        if self._skip_depth == 0 and tag in self.BLOCK_TAGS:
            self._flush()

    def close(self) -> None:
        super().close()
        self._flush()

    def _flush(self) -> None:
        line = clean_text(" ".join(self._buffer))
        self._buffer = []
        if line:
            self.lines.append(line)


def clean_text(value: str) -> str:
    value = html.unescape(value)
    return re.sub(r"\s+", " ", value).strip()


def fetch_url(url: str, timeout: int = 30) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            charset = response.headers.get_content_charset() or "utf-8"
            return response.read().decode(charset, errors="replace")
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not fetch {url}: {exc}") from exc


def parse_groups(html_text: str) -> list[Group]:
    parser = MitreGroupsParser()
    parser.feed(html_text)
    parser.close()

    text_lines = html_to_lines(html_text)
    by_id: dict[str, Group] = {}
    pending_by_href: dict[str, str] = {}

    for href, text in parser.anchors:
        match = re.fullmatch(r"/groups/(G\d+)/?", href)
        if not match:
            continue
        group_id = match.group(1)
        full_url = urllib.parse.urljoin(GROUPS_URL, href)
        if re.fullmatch(r"G\d+", text):
            by_id.setdefault(group_id, Group(id=group_id, name="", url=full_url))
            pending_by_href[href] = group_id
            continue
        if pending_by_href.get(href) == group_id and group_id in by_id:
            by_id[group_id] = Group(id=group_id, name=text, url=full_url)

    ordered: list[Group] = []

    for index, line in enumerate(text_lines):
        match = re.match(r"^(G\d{4})$", line)
        if not match:
            continue
        group_id = match.group(1)
        if group_id not in by_id:
            continue
        parsed_group = by_id[group_id]
        name = parsed_group.name or next((candidate for candidate in text_lines[index + 1 : index + 5] if candidate), "")
        description = ""
        aliases = ""
        for candidate in text_lines[index + 2 : index + 8]:
            if candidate.startswith("G") and re.fullmatch(r"G\d{4}", candidate):
                break
            if candidate and not candidate.startswith(name):
                aliases = candidate
                continue
            if candidate:
                description = candidate
                break
        ordered.append(
            Group(
                id=group_id,
                name=name,
                url=parsed_group.url,
                aliases=aliases,
                description=description,
            )
        )

    if ordered:
        return dedupe_groups(ordered)
    return list(by_id.values())


def dedupe_groups(groups: Iterable[Group]) -> list[Group]:
    seen: set[str] = set()
    result: list[Group] = []
    for group in groups:
        if group.id in seen:
            continue
        seen.add(group.id)
        result.append(group)
    return result


def html_to_lines(html_text: str) -> list[str]:
    parser = PageTextParser()
    parser.feed(html_text)
    parser.close()
    return parser.lines


def parse_group_page(
    group: Group, html_text: str, reference_sources: list[ReferenceSource] | None = None
) -> GroupPage:
    lines = html_to_lines(html_text)
    title = group.name
    sections: dict[str, list[str]] = {}
    current_section = "Overview"

    section_headings = {
        "Associated Group Descriptions",
        "Techniques Used",
        "Software",
        "Campaigns",
        "References",
    }

    for line in lines:
        if line in section_headings:
            current_section = line
            sections.setdefault(current_section, [])
            continue
        if line == group.id or line == group.name:
            title = group.name or line
            continue
        if looks_like_navigation(line):
            continue
        sections.setdefault(current_section, []).append(line)

    section_text = {key: "\n".join(compact_repeated_lines(value)) for key, value in sections.items()}
    full_text = "\n".join(lines)
    techniques = sorted(set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", full_text)))
    software = sorted(set(re.findall(r"\bS\d{4}\b", full_text)))
    summary = section_text.get("Overview", "")[:4000]

    return GroupPage(
        group=group,
        title=title,
        summary=summary,
        sections=section_text,
        techniques=techniques,
        software=software,
        reference_sources=reference_sources or [],
    )


def parse_reference_source(url: str, html_text: str, max_chars: int = 12000) -> ReferenceSource:
    lines = [
        line
        for line in html_to_lines(html_text)
        if line and not looks_like_navigation(line)
    ]
    title = extract_reference_title(lines, url)
    text = "\n".join(compact_repeated_lines(lines))
    if len(text) > max_chars:
        text = text[:max_chars] + "\n\n[Reference source truncated to fit API prompt.]"
    return ReferenceSource(url=url, title=title, text=text)


def extract_reference_title(lines: list[str], url: str) -> str:
    for line in lines[:20]:
        if re.fullmatch(r"(ID:\s*)?G\d{4}", line):
            continue
        if 8 <= len(line) <= 180:
            return line
    return urllib.parse.urlparse(url).netloc or url


def compact_repeated_lines(lines: Iterable[str]) -> list[str]:
    compacted: list[str] = []
    previous = ""
    for line in lines:
        if line == previous:
            continue
        compacted.append(line)
        previous = line
    return compacted


def looks_like_navigation(line: str) -> bool:
    return line in {
        "Home",
        "Groups",
        "Matrices",
        "Enterprise",
        "Mobile",
        "ICS",
        "Tactics",
        "Techniques",
        "Defenses",
        "Mitigations",
        "Assets",
        "Detections",
        "CTI",
        "Resources",
        "Search",
        "Blog",
        "Benefactors",
        "Contribute",
        "Enterprise Mobile ICS",
        "Detection Strategies Analytics Data Components",
        "Groups Software Campaigns",
        "Get Started Learn More about ATT&CK ATT&CK Advisory Council ATT&CKcon ATT&CK Data & Tools FAQ Engage with ATT&CK Version History Updates Legal & Branding",
        "ATT&CK v19 has been released! Check out the blog post for more information.",
    }


def choose_group(groups: list[Group], search: str | None = None) -> Group:
    candidates = groups
    if search:
        needle = search.casefold()
        candidates = [
            group
            for group in groups
            if needle in group.id.casefold()
            or needle in group.name.casefold()
            or needle in group.aliases.casefold()
        ]
        if not candidates:
            raise RuntimeError(f"No MITRE groups matched {search!r}.")

    while True:
        print_group_list(candidates)
        selected = input("\nChoose a group by number, ID, or name: ").strip()
        if not selected:
            continue
        if selected.isdigit() and 1 <= int(selected) <= len(candidates):
            return candidates[int(selected) - 1]
        lowered = selected.casefold()
        matches = [
            group
            for group in candidates
            if lowered == group.id.casefold() or lowered == group.name.casefold()
        ]
        if len(matches) == 1:
            return matches[0]
        matches = [
            group
            for group in candidates
            if lowered in group.id.casefold()
            or lowered in group.name.casefold()
            or lowered in group.aliases.casefold()
        ]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            candidates = matches
            print(f"\nNarrowed to {len(matches)} matches.")
            continue
        print("No match. Try a number from the list, a MITRE ID, or the group name.")


def print_group_list(groups: list[Group]) -> None:
    print(f"\nMITRE ATT&CK Groups ({len(groups)}):")
    for index, group in enumerate(groups, start=1):
        alias_text = f" [{group.aliases}]" if group.aliases else ""
        print(f"{index:3}. {group.id:6} {group.name}{alias_text}")


def make_prompt(page: GroupPage) -> str:
    source_context = build_source_context(page)
    return f"""
You are an experienced DFIR and threat-hunting lead.

The analyst believes the attacker may be {page.group.name} ({page.group.id}).
Use only the source context below as attributed facts. MITRE ATT&CK is the
baseline source. Additional reference URLs, when present, may contain IOCs,
tooling details, and technique analysis. You may add defensible forensic
reasoning, but label it as investigative guidance rather than sourced fact.

Create a practical incident-response playbook that tells the analyst what to
search for to find this group's tools and activity. Include:

1. Executive triage summary.
2. Likely ATT&CK techniques and what they imply for evidence collection.
3. Forensic artifacts to collect and inspect by platform or data source.
4. Tool and malware hunting targets, including filenames, services, processes,
   registry keys, scheduled tasks, network indicators, persistence mechanisms,
   and log sources when the source context supports them.
5. A Velociraptor-first collection plan. Prefer built-in Velociraptor artifact
   names with concrete arguments the analyst should run. Include artifact
   purpose, target operating system, suggested arguments, expected evidence,
   notebook post-processing VQL, and follow-up interpretation. Use raw collection
   VQL only when there is no suitable artifact, and label it clearly as optional
   custom collection VQL.
6. Suggested Velociraptor hunts grouped by priority:
   - Immediate triage hunts
   - Persistence and execution hunts
   - Credential access hunts
   - Lateral movement and remote access hunts
   - Collection/exfiltration hunts
   - Network and DNS hunts
7. Prioritized first 24-hour checklist.
8. Gaps and assumptions where MITRE does not provide enough detail.
9. Source URLs used, including MITRE and every additional reference URL.

Do not invent exact indicators of compromise. When exact IOCs are absent,
describe behavior-based searches and explain why they are relevant.

Formatting requirements:
- Use compact Markdown headings and bullet lists.
- Do not use wide Markdown tables.
- Keep lines readable and avoid padded whitespace.
- Include a "Velociraptor Artifact Runbook" section.
- For each Velociraptor artifact, show arguments in fenced YAML blocks.
- For each Velociraptor artifact, include "Expected Evidence" and
  "Notebook Post-Process VQL" subsections. The notebook VQL should assume the artifact
  collection already ran and should help filter, enrich, group, or summarize the
  collected results in a Velociraptor notebook.
- Put notebook post-processing VQL in fenced `vql` code blocks. Keep it
  artifact-specific and use placeholders for collection IDs, flow IDs, client
  IDs, time windows, or IoCs when exact values are unknown.
- Include an "External Reference Findings" section when additional URLs are
  provided. Summarize any IOCs, malware/tool names, infrastructure, filenames,
  commands, registry paths, domains, IPs, hashes, and techniques found there.
- Do not invent exact IOCs. If exact values are absent, use placeholders such
  as <suspect_host>, <date_range>, <domain>, <user>, <hash>, and explain how to
  fill them.
- Use today's date for the report date: {date.today().isoformat()}.

MITRE source URL: {page.group.url}

MITRE source context:
{source_context}
""".strip()


def build_source_context(page: GroupPage, max_chars: int = 45000) -> str:
    parts = [
        f"Group: {page.group.name}",
        f"ID: {page.group.id}",
        f"Aliases: {page.group.aliases or 'None listed in index'}",
        f"Index description: {page.group.description or 'Not captured'}",
        f"Techniques observed on page: {', '.join(page.techniques) or 'Not extracted'}",
        f"Software IDs observed on page: {', '.join(page.software) or 'Not extracted'}",
        f"Additional reference URLs: {', '.join(source.url for source in page.reference_sources) or 'None provided'}",
    ]

    for index, source in enumerate(page.reference_sources, start=1):
        parts.append(
            f"\n## Additional Reference {index}: {source.title}\n"
            f"URL: {source.url}\n"
            f"{source.text}"
        )

    for heading, content in page.sections.items():
        if content:
            parts.append(f"\n## MITRE {heading}\n{content}")

    context = "\n".join(parts)
    if len(context) <= max_chars:
        return context
    return context[:max_chars] + "\n\n[Context truncated to fit API prompt.]"


def call_ai(prompt: str, args: argparse.Namespace) -> str:
    api_key = (
        args.api_key
        or os.getenv("OPENROUTER_API_KEY")
        or os.getenv("AI_API_KEY")
        or os.getenv("OPENAI_API_KEY")
    )
    if not api_key and sys.stdin.isatty():
        api_key = getpass.getpass("OpenRouter API key: ").strip()
    if not api_key:
        raise RuntimeError(
            "Missing API key. Set OPENROUTER_API_KEY, AI_API_KEY, or pass --api-key."
        )

    base_url = (
        args.api_base_url
        or os.getenv("OPENROUTER_BASE_URL")
        or os.getenv("AI_API_BASE_URL")
        or DEFAULT_API_BASE_URL
    ).rstrip("/")
    model = (
        args.model
        or os.getenv("OPENROUTER_MODEL")
        or os.getenv("AI_MODEL")
        or DEFAULT_MODEL
    )

    if args.api_style == "responses":
        return call_responses_api(base_url, api_key, model, prompt)
    return call_chat_completions_api(base_url, api_key, model, prompt)


def call_chat_completions_api(base_url: str, api_key: str, model: str, prompt: str) -> str:
    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "You produce precise, source-aware DFIR playbooks for security analysts.",
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
        "max_tokens": DEFAULT_MAX_TOKENS,
    }
    data = post_json(f"{base_url}/chat/completions", api_key, payload)
    return extract_chat_completion_text(data)


def call_responses_api(base_url: str, api_key: str, model: str, prompt: str) -> str:
    payload = {
        "model": model,
        "input": [
            {
                "role": "system",
                "content": "You produce precise, source-aware DFIR playbooks for security analysts.",
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
        "max_output_tokens": DEFAULT_MAX_TOKENS,
    }
    data = post_json(f"{base_url}/responses", api_key, payload)
    chunks: list[str] = []
    for item in data.get("output", []):
        for content in item.get("content", []):
            if content.get("type") in {"output_text", "text"}:
                chunks.append(content.get("text", ""))
    if chunks:
        return "\n".join(chunks).strip()
    if "output_text" in data:
        return str(data["output_text"])
    raise RuntimeError("Could not find text in Responses API result.")


def extract_chat_completion_text(data: dict) -> str:
    choices = data.get("choices") or []
    if not choices:
        raise RuntimeError(f"AI API returned no choices: {json.dumps(data)[:1000]}")

    message = choices[0].get("message") or {}
    content = message.get("content")
    if isinstance(content, str) and content.strip():
        return content
    if isinstance(content, list):
        chunks = []
        for item in content:
            if isinstance(item, dict):
                chunks.append(str(item.get("text") or item.get("content") or ""))
            else:
                chunks.append(str(item))
        text = "\n".join(chunk for chunk in chunks if chunk).strip()
        if text:
            return text

    raise RuntimeError(f"AI API returned an empty message: {json.dumps(data)[:1000]}")


def sanitize_generated_text(content: str) -> str:
    """Remove pathological whitespace sometimes returned by routed models."""

    lines = []
    blank_count = 0
    for raw_line in content.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = re.sub(r"[ \t]{3,}", " ", raw_line).rstrip()
        if not line:
            blank_count += 1
            if blank_count <= 2:
                lines.append("")
            continue
        blank_count = 0
        lines.append(line)
    return "\n".join(lines).strip() + "\n"


def default_output_path(group: Group, no_ai: bool = False) -> str:
    suffix = "prompt-preview" if no_ai else "playbook"
    return f"{safe_filename_part(group.name or group.id)}-{suffix}.md"


def safe_filename_part(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip())
    cleaned = cleaned.strip("-._")
    return cleaned or "apt-group"


def post_json(url: str, api_key: str, payload: dict) -> dict:
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
    }
    if "openrouter.ai" in urllib.parse.urlparse(url).netloc:
        headers["X-Title"] = os.getenv("OPENROUTER_APP_TITLE", OPENROUTER_TITLE)
        site_url = os.getenv("OPENROUTER_SITE_URL")
        if site_url:
            headers["HTTP-Referer"] = site_url

    request = urllib.request.Request(
        url,
        data=body,
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            charset = response.headers.get_content_charset() or "utf-8"
            return json.loads(response.read().decode(charset, errors="replace"))
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"AI API request failed with HTTP {exc.code}: {error_body}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"AI API request failed: {exc}") from exc


def write_output(path: str, content: str) -> None:
    output_path = os.path.abspath(path)
    temp_path = f"{output_path}.tmp"
    with open(temp_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(sanitize_generated_text(content))
    os.replace(temp_path, output_path)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a DFIR playbook for a selected MITRE ATT&CK group."
    )
    parser.add_argument("--groups-url", default=GROUPS_URL, help="MITRE groups index URL.")
    parser.add_argument("--search", help="Pre-filter groups by ID, name, or alias.")
    parser.add_argument(
        "--reference-url",
        action="append",
        default=[],
        help="Additional investigation/report URL with IOCs or techniques. Can be used multiple times.",
    )
    parser.add_argument("--no-ai", action="store_true", help="Fetch and summarize the group page without calling the AI API.")
    parser.add_argument(
        "--output",
        help="Write output to this file. Default: <group>-playbook.md. Use '-' to print to stdout.",
    )
    parser.add_argument("--api-key", help="AI API key. Prefer OPENROUTER_API_KEY env var.")
    parser.add_argument("--api-base-url", help=f"AI API base URL. Default: {DEFAULT_API_BASE_URL}")
    parser.add_argument("--model", help=f"AI model. Default: {DEFAULT_MODEL}")
    parser.add_argument(
        "--api-style",
        choices=("chat", "responses"),
        default=os.getenv("AI_API_STYLE", "chat"),
        help="Use OpenAI-compatible chat/completions or the OpenAI Responses API. Use chat for OpenRouter.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    print(f"Fetching MITRE groups from {args.groups_url} ...")
    groups_html = fetch_url(args.groups_url)
    groups = parse_groups(groups_html)
    if not groups:
        raise RuntimeError("No groups were found on the MITRE groups page.")

    group = choose_group(groups, args.search)
    print(f"\nSelected {group.name} ({group.id})")
    print(f"Fetching group page: {group.url}")
    group_html = fetch_url(group.url)
    reference_sources = []
    for reference_url in args.reference_url:
        print(f"Fetching additional reference: {reference_url}")
        reference_html = fetch_url(reference_url)
        reference_sources.append(parse_reference_source(reference_url, reference_html))

    page = parse_group_page(group, group_html, reference_sources=reference_sources)
    prompt = make_prompt(page)

    if args.no_ai:
        output = "\n".join(
            [
                "AI call skipped.",
                "",
                f"Selected group: {group.name} ({group.id})",
                f"Source URL: {group.url}",
                f"Additional reference URLs: {', '.join(args.reference_url) or 'None'}",
                "",
                "Prompt/context prepared for the AI:",
                "",
                prompt,
            ]
        )
    else:
        print("Requesting AI-generated DFIR playbook ...")
        output = sanitize_generated_text(call_ai(prompt, args))

    output_path = args.output or default_output_path(group, no_ai=args.no_ai)
    if output_path != "-":
        write_output(output_path, output)
        print(f"\nWrote output to {output_path}")
    else:
        print("\n" + output)

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        raise SystemExit(130)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
