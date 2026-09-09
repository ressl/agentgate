"""Execute dashboard JavaScript to check live response accounting."""

import re
import shutil
import subprocess

import pytest

from mcp_firewall.dashboard.app import DASHBOARD_HTML


@pytest.mark.skipif(shutil.which("node") is None, reason="JavaScript runtime unavailable")
def test_live_dashboard_counters_include_responses_without_extra_calls():
    script = re.search(r"<script>(.*?)</script>", DASHBOARD_HTML, re.S).group(1)
    harness = r"""
const vm = require('node:vm');
const assert = require('node:assert/strict');
let source = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => source += chunk);
process.stdin.on('end', async () => {
  function element() {
    return {children: [], textContent: '',
      appendChild(item) {this.children.push(item)},
      insertBefore(item) {this.children.unshift(item)},
      removeChild(item) {this.children.splice(this.children.indexOf(item), 1)},
      get firstChild() {return this.children[0]},
      get lastChild() {return this.children.at(-1)}
    };
  }
  const nodes = new Map();
  const document = {
    getElementById(id) {if (!nodes.has(id)) nodes.set(id, element()); return nodes.get(id)},
    createElement: element
  };
  const context = {document, location: {host: 'test'}, Date, JSON, Math,
    WebSocket: class {}, setInterval() {}, setTimeout() {},
    fetch: async url => ({json: async () => url.includes('stats') ? {
      stats: {total: 0, allowed: 0, denied: 0, redacted: 0, responses_denied: 0}, uptime: 0
    } : []})
  };
  vm.runInNewContext(source, context);
  await new Promise(resolve => setImmediate(resolve));
  context.addEvent({action: 'allow', tool: 'status'});
  context.addEvent({action: 'redact', direction: 'outbound', tool: 'status'});
  context.addEvent({action: 'deny', direction: 'outbound', tool: 'status'});
  context.addEvent({action: 'deny', direction: 'outbound', replay: true});
  for (const [name, value] of Object.entries({total: 1, allowed: 1, denied: 0,
      redacted: 1, 'responses-denied': 1})) {
    assert.equal(nodes.get('stat-' + name).textContent, value, name);
  }
});
"""
    result = subprocess.run(
        [shutil.which("node"), "-e", harness],
        input=script,
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
