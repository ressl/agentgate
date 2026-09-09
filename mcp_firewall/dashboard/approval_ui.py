"""Local approval controls; credentials live only in the current page's memory."""

APPROVAL_HTML = """
<section class="feed" id="approval-panel" hidden aria-label="Human approvals">
  <div class="card">
    <h2>Human approvals</h2>
    <p id="approval-status" role="status" aria-live="polite">
      Disconnected. Calls requiring approval are denied.
    </p>
    <form id="approval-connect-form" style="margin: 12px 0">
      <label for="approval-token">Controller token</label>
      <input id="approval-token" type="password" autocomplete="off" spellcheck="false"
        required minlength="32" maxlength="1024" style="margin: 8px; padding: 8px; max-width: 100%">
      <button id="approval-connect" type="submit">Connect</button>
      <button id="approval-disconnect" type="button" hidden>Disconnect</button>
    </form>
    <p style="color: var(--dim); font-size: 13px; margin-bottom: 12px">
      Keep this page active. Each approval applies once; remaining security checks still run.
    </p>
    <div id="approval-list"></div>
  </div>
</section>
"""

APPROVAL_SCRIPT = """
<script>
(() => {
  const panel = document.getElementById('approval-panel');
  const status = document.getElementById('approval-status');
  const input = document.getElementById('approval-token');
  const connect = document.getElementById('approval-connect');
  const disconnect = document.getElementById('approval-disconnect');
  const list = document.getElementById('approval-list');
  let token = '', generation = 0, timer;

  async function api(path, credential, body) {
    const abort = new AbortController();
    const timeout = setTimeout(() => abort.abort(), 3000);
    try {
      const response = await fetch(path, {
        method: body === undefined ? 'GET' : 'POST',
        headers: {'Authorization': 'Bearer ' + credential, 'Content-Type': 'application/json'},
        body: body === undefined ? undefined : JSON.stringify(body),
        cache: 'no-store', credentials: 'omit', redirect: 'error', signal: abort.signal
      });
      if (!response.ok) {
        const error = new Error('Approval request failed');
        error.status = response.status;
        throw error;
      }
      return await response.json();
    } finally { clearTimeout(timeout); }
  }

  function stop(message) {
    generation++;
    clearTimeout(timer);
    token = '';
    input.value = '';
    input.disabled = false;
    connect.disabled = false;
    connect.hidden = false;
    disconnect.hidden = true;
    list.replaceChildren();
    status.textContent = message;
  }

  function render(items, version) {
    const ids = new Set(items.map(item => item.id));
    for (const card of Array.from(list.children)) {
      if (!ids.has(card.dataset.approvalId)) card.remove();
    }
    for (const item of items) {
      // Keep existing controls stable across polls, including keyboard focus.
      if (Array.from(list.children).some(card => card.dataset.approvalId === item.id)) continue;
      const card = document.createElement('article');
      card.dataset.approvalId = item.id;
      card.className = 'card';
      card.style.marginTop = '12px';
      const title = document.createElement('h3');
      title.textContent = item.tool;
      const agent = document.createElement('p');
      agent.textContent = 'Agent: ' + item.agent + ' · Expires ' +
        new Date(item.expires_at * 1000).toLocaleTimeString();
      const preview = document.createElement('pre');
      preview.textContent = item.arguments_preview;
      preview.style.cssText = 'white-space: pre-wrap; overflow-wrap: anywhere; margin: 12px 0;' +
        'max-height: 260px; overflow: auto';
      card.append(title, agent, preview);
      if (item.redacted) {
        const notice = document.createElement('p');
        notice.textContent = 'Sensitive values are redacted. Deny if you cannot assess this call.';
        notice.style.color = 'var(--yellow)';
        card.append(notice);
      }
      const allow = document.createElement('button');
      const deny = document.createElement('button');
      allow.textContent = 'Allow once';
      deny.textContent = 'Deny';
      for (const [button, decision] of [[allow, true], [deny, false]]) {
        button.type = 'button';
        button.style.cssText = 'padding: 8px 14px; margin: 12px 8px 0 0; cursor: pointer';
        button.addEventListener('click', async () => {
          if (!token || version !== generation) return;
          allow.disabled = deny.disabled = true;
          try {
            await api('/api/approvals/' + encodeURIComponent(item.id), token,
              {request_hash: item.request_hash, allow: decision});
            if (version === generation) card.remove();
          } catch (error) {
            if (version !== generation) return;
            if (error.status === 409) {
              card.remove();
              status.textContent = 'This request has expired or changed. Waiting for new calls.';
            } else {
              stop('Connection lost. Pending calls will be denied. Reconnect to continue.');
            }
          }
        });
        card.append(button);
      }
      list.append(card);
    }
  }

  async function poll(version) {
    if (!token || version !== generation) return;
    try {
      const items = await api('/api/approvals', token);
      if (version !== generation) return;
      render(items, version);
      status.textContent = items.length
        ? 'Review pending calls below.' : 'Connected. Waiting for calls.';
      connect.hidden = true;
      disconnect.hidden = false;
      timer = setTimeout(() => poll(version), 2000);
    } catch (_) {
      if (version === generation) stop('Connection failed. Check the token and reconnect.');
    }
  }

  document.getElementById('approval-connect-form').addEventListener('submit', event => {
    event.preventDefault();
    if (connect.disabled || !input.value) return;
    token = input.value;
    input.value = '';
    input.disabled = connect.disabled = true;
    status.textContent = 'Connecting…';
    poll(++generation);
  });
  disconnect.addEventListener('click', async () => {
    const credential = token;
    stop('Disconnected. Calls requiring approval are denied.');
    try { await api('/api/approvals/disconnect', credential, {}); } catch (_) {}
  });
  window.addEventListener('pagehide', () => {
    if (!token) return;
    const credential = token;
    stop('Disconnected. Reconnect to continue.');
    fetch('/api/approvals/disconnect', {
      method: 'POST', headers: {'Authorization': 'Bearer ' + credential},
      keepalive: true, credentials: 'omit', redirect: 'error'
    }).catch(() => {});
  });
  fetch('/api/approval-mode', {cache: 'no-store'}).then(response => response.json())
    .then(mode => { panel.hidden = !mode.enabled; }).catch(() => {});
})();
</script>
"""
