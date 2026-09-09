#!/usr/bin/env python3
"""Apply the adapter to a clean, pinned AgentReins development checkout."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

UPSTREAM_COMMIT = "dbd4f0abe3ff2d2cd590ac4f7b8e144d7375edbb"
ROOT = Path(__file__).resolve().parent


def git(checkout: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(checkout), *args], text=True).strip()  # noqa: S603,S607


def install(checkout: Path) -> None:
    checkout = checkout.resolve(strict=True)
    if git(checkout, "rev-parse", "HEAD") != UPSTREAM_COMMIT:
        raise ValueError(f"Use AgentReins commit {UPSTREAM_COMMIT}; newer sources need review")
    if git(checkout, "status", "--porcelain"):
        raise ValueError("AgentReins checkout must be clean; preserve existing edits first")
    app = checkout / "Sources/AgentReins/AgentGuardApp.swift"
    source = app.read_text()
    state_anchor = "    @StateObject private var codexSight = CodexSight()"
    replacements = {
        state_anchor: state_anchor + "\n"
        "    @StateObject private var mcpFirewall = MCPFirewallSight()\n"
        "    @State private var showingFirewall = false",
        "            ContentView()": "            ContentView()\n"
        '                .toolbar { Button("MCP Firewall") { showingFirewall = true } }\n'
        "                .sheet(isPresented: $showingFirewall) {\n"
        "                    MCPFirewallView(sight: mcpFirewall)\n"
        "                }",
        "                .task {": "                .task {\n"
        "                    mcpFirewall.onEvents = { eventStore.record($0) }",
    }
    for old, new in replacements.items():
        if source.count(old) != 1:
            raise ValueError(
                "AgentReins app wiring changed; review the integration before applying"
            )
        source = source.replace(old, new, 1)
    edits = {app: source}
    compatibility = {
        "AgentSession.swift": [
            (
                'let completion = callEvents.first(where: { $0.op == "result" })',
                'let completion = callEvents.first(where: { $0.op == "result"'
                ' || $0.op == "firewall_outcome" })',
            ),
            (
                "completedAt: completion?.ts, traceId: call.traceId,",
                "completedAt: completion?.isMCPFirewall == true ? nil : compl"
                "etion?.ts, traceId: call.traceId,",
            ),
        ],
        "SecurityIncident.swift": [
            (
                'var wasBlocked: Bool { events.contains { $0.action == "block" } }',
                'var wasBlocked: Bool { events.contains { $0.action == "block'
                '" || $0.isMCPFirewallBlock } }',
            ),
            (
                "var title: String {",
                "var title: String {\n        if let title = mcpFirewallTitle { return title }",
            ),
            (
                "var summary: String {",
                "var summary: String {\n        if let summary = mcpFirewallSu"
                "mmary { return summary }",
            ),
            (
                "var causalChain: [Stage] {\n        [",
                "var causalChain: [Stage] {\n        if let chain = mcpFirewal"
                "lChain { return chain }\n        return [",
            ),
        ],
        "DevelopmentTrace.swift": [
            (
                "        let intent = turn.userInput ?? session.latestIntent",
                "        if let trace = mcpFirewallTrace(session: session, tu"
                "rn: turn) { return trace }\n        let intent = turn.userInp"
                "ut ?? session.latestIntent",
            ),
        ],
        "ContentView.swift": [
            (
                "    private func liveContextTitle(_ event: GuardEvent, toolN"
                "ame: String?) -> String {",
                "    private func liveContextTitle(_ event: GuardEvent, toolN"
                "ame: String?) -> String {\n        if event.isMCPFirewall { r"
                "eturn event.action }",
            ),
        ],
    }
    for name, patches in compatibility.items():
        target = checkout / "Sources/AgentReins" / name
        text = target.read_text()
        for old, new in patches:
            if text.count(old) != 1:
                raise ValueError(f"Evidence presentation changed in {name}; review before applying")
            text = text.replace(old, new, 1)
        edits[target] = text
    copies = [
        (path, checkout / "Sources/AgentReins" / path.name)
        for path in sorted((ROOT / "Sources").glob("*.swift"))
    ] + [
        (path, checkout / "Tests/AgentReinsTests" / path.name)
        for path in sorted((ROOT / "Tests").glob("*.swift"))
    ]
    for _, target in copies:
        if target.exists():
            raise ValueError(f"Refusing to overwrite existing adapter file: {target.name}")
    for origin, target in copies:
        target.write_bytes(origin.read_bytes())
    for target, text in edits.items():
        target.write_text(text)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkout", type=Path)
    args = parser.parse_args()
    try:
        install(args.checkout)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Adapter installation stopped: {error}\n")
    print("Adapter installed. Run swift test, then open MCP Firewall in the app toolbar.")


if __name__ == "__main__":
    main()
