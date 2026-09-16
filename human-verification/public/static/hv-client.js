/* Shared browser helpers for the verification and diagnostics pages. */
(function (global) {
  'use strict';

  async function api(path, opts) {
    opts = opts || {};
    const headers = { 'content-type': 'application/json' };
    if (opts.clientToken) headers['x-client-token'] = opts.clientToken;
    const res = await fetch(path, { method: opts.method || 'GET', headers, body: opts.body ? JSON.stringify(opts.body) : undefined, credentials: 'omit' });
    let body = null;
    try { body = await res.json(); } catch (_) { body = null; }
    return { status: res.status, body };
  }

  function fragmentParams() {
    const out = {};
    const raw = (location.hash || '').replace(/^#/, '');
    raw.split('&').forEach(function (kv) {
      if (!kv) return;
      const i = kv.indexOf('=');
      const k = decodeURIComponent(i < 0 ? kv : kv.slice(0, i));
      const v = decodeURIComponent(i < 0 ? '' : kv.slice(i + 1));
      out[k] = v;
    });
    return out;
  }

  function el(tag, attrs, children) {
    const node = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      if (k === 'class') node.className = attrs[k];
      else if (k === 'text') node.textContent = attrs[k];
      else if (k.indexOf('data-') === 0 || k === 'id' || k === 'href' || k === 'type' || k === 'for') node.setAttribute(k, attrs[k]);
      else node[k] = attrs[k];
    });
    (children || []).forEach(function (ch) { node.appendChild(typeof ch === 'string' ? document.createTextNode(ch) : ch); });
    return node;
  }

  function renderPolicy(policy) {
    const wrap = el('div', { 'data-testid': 'policy-result' });
    if (!policy) { wrap.appendChild(el('p', { class: 'muted', text: 'No policy evaluation available.' })); return wrap; }
    const head = el('p', {}, [
      el('strong', { text: 'Attestation policy ' + policy.policyVersion + ': ' }),
      el('span', { class: policy.trusted ? 'ok' : 'bad', text: policy.outcome, 'data-testid': 'policy-outcome' }),
      policy.rejectionCodes && policy.rejectionCodes.length ? el('span', { class: 'muted', text: ' (' + policy.rejectionCodes.join(', ') + ')' }) : el('span'),
    ]);
    wrap.appendChild(head);
    const ev = policy.evidence || {};
    wrap.appendChild(el('p', { class: 'muted', text: 'fmt=' + ev.fmt + ' · aaguid=' + (ev.aaguid || '-') + ' · chain=' + (ev.chain && ev.chain.present ? ev.chain.length + ' cert(s), valid=' + ev.chain.valid + ', anchor=' + (ev.chain.anchorLabel || 'none') : 'absent') + ' · flags UV=' + (ev.flags && ev.flags.uv ? 1 : 0) + ' BE=' + (ev.flags && ev.flags.be ? 1 : 0) + ' BS=' + (ev.flags && ev.flags.bs ? 1 : 0) }));
    const table = el('table');
    table.appendChild(el('thead', {}, [el('tr', {}, [el('th', { text: 'Check' }), el('th', { text: 'Result' }), el('th', { text: 'Basis' }), el('th', { text: 'Detail' })])]));
    const tb = el('tbody');
    (policy.checks || []).forEach(function (c) {
      tb.appendChild(el('tr', {}, [el('td', {}, [el('code', { text: c.id })]), el('td', {}, [el('span', { class: 'badge ' + c.result, text: c.result })]), el('td', { class: 'muted', text: c.basis }), el('td', { text: c.detail })]));
    });
    table.appendChild(tb);
    wrap.appendChild(table);
    return wrap;
  }

  function describeError(err) {
    return { name: err && err.name, message: err && err.message, code: err && err.code, cause: err && err.cause ? String(err.cause) : undefined };
  }

  function isMobileUa() { return /Android|iPhone|iPad|iPod/i.test(navigator.userAgent); }

  global.HV = { api: api, fragmentParams: fragmentParams, el: el, renderPolicy: renderPolicy, describeError: describeError, isMobileUa: isMobileUa };
})(window);
