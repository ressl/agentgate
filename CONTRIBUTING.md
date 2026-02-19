# Contributing to mcp-firewall

Thanks for your interest in making AI agents more secure!

## Getting Started

```bash
git clone https://github.com/ressl/mcp-firewall.git
cd mcp-firewall
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Development

- **Style:** Enforced by `ruff` (run `ruff check .` and `ruff format .`)
- **Types:** Enforced by `mypy --strict`
- **Tests:** Required for all new features (`pytest`)
- **Commits:** Conventional commits preferred (`feat:`, `fix:`, `docs:`)

## Threat Feed Rules

Community rules are welcome! To contribute a detection rule:

1. Create a YAML file in `threatfeed/rules/`
2. Follow the existing format (see `threatfeed/rules/` for examples)
3. Include: id, name, severity, description, match pattern, action
4. Test against the vulnerable example server
5. Submit a PR

## Policies

If you have a useful OPA/Rego policy for a specific use case (healthcare, finance, etc.), consider contributing it to `examples/policies/`.

## Code of Conduct

Be respectful. Be constructive. Focus on making AI agents safer for everyone.
