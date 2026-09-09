# Contributing to mcp-firewall

Thanks for your interest in making AI agents more secure!

## Getting Started

```bash
git clone https://github.com/ressl/mcp-firewall.git
cd mcp-firewall
python -m venv .venv
source .venv/bin/activate
pip install -r requirements/ci.txt -e ".[dev]"
pytest
```

## Development

- **Style:** `ruff check .` and `ruff format --check .` (apply formatting with `ruff format .`)
- **Types:** `mypy mcp_firewall` (strict mode is configured in `pyproject.toml`)
- **Tests:** Required for all new features (`pytest`)
- **Commits:** Conventional commits preferred (`feat:`, `fix:`, `docs:`)

CI runs the full suite on Python 3.11–3.14 under Linux and Python 3.11 under macOS,
plus the real [AgentReins integration](integrations/agentreins/README.md). Packaging
builds and installs both archives in isolation. See [release validation](docs/releases.md)
for job coverage, build identity and the publication procedure.

## Threat Feed Rules

Community rules are welcome! To contribute a detection rule:

1. Create a YAML file in `threatfeed/rules/`
2. Follow the existing format (see `threatfeed/rules/` for examples)
3. Include: id, name, severity, description, match pattern, action
4. Test against the vulnerable example server
5. Submit a PR

## Policies

If you have a useful YAML policy for a specific use case (healthcare, finance, etc.), consider contributing it to `examples/policies/`.

## Code of Conduct

Be respectful. Be constructive. Focus on making AI agents safer for everyone.
