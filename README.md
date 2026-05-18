# APT Playbook Builder

Small Python CLI that lists MITRE ATT&CK groups from:

https://attack.mitre.org/groups/

After the analyst chooses a group, the tool fetches that group's MITRE page and
asks an AI API to create a Velociraptor-first DFIR playbook for finding that
group's tools, techniques, and forensic traces.

## Requirements

- Python 3.10+
- Network access to `attack.mitre.org`
- An OpenRouter API key for playbook generation

No third-party Python packages are required.

## Usage

```powershell
python .\apt_playbook_builder.py
```

By default, the report is written to `<group>-playbook.md`, for example
`APT29-playbook.md`.

Filter the group list before choosing:

```powershell
python .\apt_playbook_builder.py --search APT29
```

Add external investigation reports with IOCs or technique analysis:

```powershell
python .\apt_playbook_builder.py `
  --search APT29 `
  --reference-url "https://example.com/vendor-report-about-apt29" `
  --reference-url "https://example.com/another-ioc-report"
```

Each additional URL is fetched, added to the AI source context, and listed in
the final playbook sources.

Write the playbook to a Markdown file:

```powershell
python .\apt_playbook_builder.py --search APT29 --output APT29-playbook.md
```

Print to the console instead of writing a file:

```powershell
python .\apt_playbook_builder.py --search APT29 --output -
```

Preview the source context and prompt without calling the AI API:

```powershell
python .\apt_playbook_builder.py --search APT29 --no-ai
```

This writes `APT29-prompt-preview.md` by default.

## API Configuration

Set the OpenRouter API key in the environment:

```powershell
$env:OPENROUTER_API_KEY = "your-key"
python .\apt_playbook_builder.py --search APT29
```

If no key is configured and you run the tool interactively, it will prompt for
the OpenRouter key without echoing it to the terminal.

Optional environment variables:

- `OPENROUTER_API_KEY`
- `OPENROUTER_BASE_URL`, default `https://openrouter.ai/api/v1`
- `OPENROUTER_MODEL`, default `openrouter/auto`
- `OPENROUTER_APP_TITLE`, optional app title sent to OpenRouter
- `OPENROUTER_SITE_URL`, optional site URL sent to OpenRouter
- `AI_API_STYLE`, default `chat`

OpenRouter uses an OpenAI-compatible chat completions endpoint, so keep
`AI_API_STYLE=chat`.

Equivalent CLI options are also available:

```powershell
python .\apt_playbook_builder.py `
  --search APT29 `
  --api-key "your-key" `
  --api-base-url "https://openrouter.ai/api/v1" `
  --model "openrouter/auto" `
  --api-style chat
```

You can replace `openrouter/auto` with any OpenRouter model slug:

```powershell
$env:OPENROUTER_MODEL = "provider/model-name"
python .\apt_playbook_builder.py --search APT29 --output APT29-playbook.md
```

## Output

The generated playbook asks the AI to include:

- Triage summary
- ATT&CK techniques and evidence implications
- Forensic artifacts by platform and data source
- Tool and malware hunting targets
- Velociraptor artifact runbook with suggested built-in artifact names,
  arguments, purpose, expected evidence, notebook post-processing VQL, and
  follow-up interpretation
- Notebook post-processing VQL for filtering, grouping, enriching, or summarizing
  collected artifact results in Velociraptor notebooks
- Optional custom collection VQL only where no suitable artifact is available
- Priority-grouped Velociraptor hunts for triage, persistence, execution,
  credential access, lateral movement, collection, exfiltration, network, and DNS
- External reference findings when `--reference-url` is provided, including IOCs,
  malware/tool names, infrastructure, filenames, commands, registry paths,
  domains, IPs, hashes, and techniques found in those sources
- First 24-hour checklist
- Gaps and assumptions
- MITRE source URL and any additional reference URLs

The prompt instructs the AI not to invent exact IOCs. When MITRE does not
provide exact indicators, the playbook should use behavior-based searches.

## Tests

```powershell
python -m unittest
```
