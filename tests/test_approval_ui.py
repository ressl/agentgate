"""Execute controller JavaScript, including polling and credential cleanup."""

import re
import shutil
import subprocess

import pytest

from mcp_firewall.dashboard.approval_ui import APPROVAL_SCRIPT


@pytest.mark.skipif(shutil.which("node") is None, reason="JavaScript runtime unavailable")
def test_approval_controls_keep_focus_bind_decisions_and_clear_credentials():
    script = re.search(r"<script>(.*?)</script>", APPROVAL_SCRIPT, re.S).group(1)
    harness = r"""
const vm = require('node:vm');
const assert = require('node:assert/strict');
let source = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => source += chunk);
process.stdin.on('end', async () => {
  class Element {
    constructor() {
      this.children = []; this.dataset = {}; this.style = {}; this.handlers = {};
      this.value = ''; this.disabled = false; this.hidden = false;
    }
    set innerHTML(_) {throw new Error('Unsafe HTML rendering')}
    append(...items) {for (const item of items) {item.parent = this; this.children.push(item)}}
    replaceChildren(...items) {this.children = []; this.append(...items)}
    remove() {this.parent.children = this.parent.children.filter(item => item !== this)}
    addEventListener(name, handler) {this.handlers[name] = handler}
  }
  const nodes = new Map();
  const get = id => {
    if (!nodes.has(id)) nodes.set(id, new Element());
    return nodes.get(id);
  };
  const item = {id: 'one', request_hash: 'a'.repeat(64), tool: '<img src=x onerror=alert(1)>',
    agent: 'local', arguments_preview: '{"password":"[REDACTED]"}', redacted: true,
    expires_at: Date.now() / 1000 + 60};
  let pending = [item], poll, fail = false;
  const requests = [];
  const context = {
    document: {getElementById: get, createElement: () => new Element()},
    window: {addEventListener() {}}, AbortController, Date, JSON, Set, Array,
    setTimeout(fn, ms) {if (ms === 2000) poll = fn; return fn}, clearTimeout() {},
    fetch: async (url, options) => {
      requests.push({url, options});
      if (url.endsWith('approval-mode')) return {json: async () => ({enabled: true})};
      if (fail) return {ok: false, status: 401};
      if (options.method === 'POST') pending = [];
      return {ok: true, json: async () => options.method === 'GET' ? pending : {accepted: true}};
    }
  };
  vm.runInNewContext(source, context);
  const flush = () => new Promise(resolve => setImmediate(resolve));
  await flush();
  get('approval-token').value = 'synthetic-controller-token-'.repeat(2);
  get('approval-connect-form').handlers.submit({preventDefault() {}});
  await flush();
  assert.equal(get('approval-token').value, '');
  assert.equal(get('approval-token').disabled, true);
  const card = get('approval-list').children[0];
  assert.equal(card.children[0].textContent, item.tool);
  assert.equal(card.children[2].textContent, item.arguments_preview);
  await poll();
  assert.equal(get('approval-list').children[0], card, 'polling must retain buttons and focus');
  const allow = card.children.find(child => child.textContent === 'Allow once');
  await allow.handlers.click();
  const decision = requests.find(request => request.url === '/api/approvals/one');
  assert.deepEqual(JSON.parse(decision.options.body),
    {request_hash: item.request_hash, allow: true});
  assert.ok(decision.options.headers.Authorization.startsWith('Bearer synthetic-'));
  assert.equal(get('approval-list').children.length, 0);
  fail = true;
  await poll();
  assert.equal(get('approval-token').value, '');
  assert.equal(get('approval-token').disabled, false);
  assert.equal(get('approval-connect').hidden, false);
  const count = requests.length;
  await allow.handlers.click();
  assert.equal(requests.length, count, 'a detached button cannot act after disconnect');
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
