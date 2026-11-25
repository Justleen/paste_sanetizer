// ==UserScript==
// @name         Paste Sanitizer
// @namespace    https://github.com/Justleen/paste_sanetizer
// @homepageURL  https://github.com/Justleen/paste_sanitizer
// @supportURL   https://github.com/Justleen/paste_sanitizer/issues
// @version      1.6.0
// @description  Find & replace text when you paste using your own dictionary (literal strings or regex).
// @match        *://*/*
// @run-at       document-start
// @all-frames   true
// @grant        GM_getValue
// @grant        GM_setValue
// @grant        GM_registerMenuCommand
// ==/UserScript==

(function () {
  'use strict';

  // ---------------------------------------------------------------------------
  // Defaults
  // ---------------------------------------------------------------------------
  const DEFAULT_RULES = `# One rule per line:   find => replace
# Several keywords:     one | two | three => replace   (use \\| for a literal |)
# Regex rule:           /pattern/flags => replace    ($1, $2 … for groups)
# Empty right side deletes the match. \\n and \\t work in the replacement.
# Lines starting with # are comments. Rules run top to bottom.
# Order: keyword rules → built-in detectors (IP, user, password, domain) → regex rules.

john.doe@acme.com | jdoe | John Doe => [ME]
Acme Corp | Acme BV | ACME => [COMPANY]
/\\b(?!(?:USERNAME|PASSWD)@)[\\w.+-]+@[\\w-]+(?:\\.[\\w-]+)*\\.[a-z]{2,}\\b/i => [EMAIL]
/\\b[A-Z]{2}\\d{2}[A-Z0-9]{10,30}\\b/ => [IBAN]
/(api[_-]?key\\s*[:=]\\s*)\\S+/i => $1[REDACTED]
`;

  const DEFAULTS = {
    rulesText: DEFAULT_RULES,
    notify: true,
    detectIP: true,
    detectFQDN: true,
    fqdnDummy: 'example.com',
    fqdnNumbered: true,
    detectUser: true,
    detectPass: true,
    disabledHosts: [],
  };

  const get = (k) => GM_getValue(k, DEFAULTS[k]);
  const set = (k, v) => GM_setValue(k, v);
  const host = location.hostname;
  const enabledHere = () => !get('disabledHosts').includes(host);

  // ---------------------------------------------------------------------------
  // Rule parsing
  // ---------------------------------------------------------------------------
  const unescape = (s) =>
    (s || '').replace(/\\(n|t|\\)/g, (_, c) => (c === 'n' ? '\n' : c === 't' ? '\t' : '\\'));

  function parseRules(text) {
    const rules = [];
    const errors = [];
    text.split(/\r?\n/).forEach((raw, i) => {
      const line = raw.trim();
      if (!line || line.startsWith('#')) return;

      const rx = line.match(/^\/(.+)\/([dimsuvy]*)\s+=>(?:\s(.*))?$/);
      if (rx) {
        try {
          const flags = rx[2].includes('g') ? rx[2] : rx[2] + 'g';
          rules.push({ type: 'regex', re: new RegExp(rx[1], flags), replace: unescape(rx[3]) });
        } catch (err) {
          errors.push(`Line ${i + 1}: ${err.message}`);
        }
        return;
      }

      const lit = line.match(/^(.*?)\s+=>(?:\s(.*))?$/);
      if (lit && lit[1]) {
        // "a | b | c => x": split on unescaped |, longest first so "Acme Corp" beats "Acme"
        const keys = lit[1].split(/(?<!\\)\|/)
          .map((k) => k.trim().replace(/\\\|/g, '|'))
          .filter(Boolean)
          .sort((a, b) => b.length - a.length);
        if (!keys.length) errors.push(`Line ${i + 1}: no keywords before "=>"`);
        const replace = unescape(lit[2]);
        for (const find of keys) rules.push({ type: 'literal', find, replace });
      } else {
        errors.push(`Line ${i + 1}: expected "find => replace"`);
      }
    });
    return { rules, errors };
  }


  // ---------------------------------------------------------------------------
  // Built-in detectors (run before your dictionary)
  // ---------------------------------------------------------------------------
  const TOK = { ip: 'IPADDR', user: 'USERNAME', pass: 'PASSWD' };
  const VAL = /("[^"\n]*"|'[^'\n]*'|[^\s"'&;,]+)/.source; // quoted or bare value
  const IS_TOKEN = /^["']?(?:USERNAME|PASSWD|IPADDR)\b/; // already sanitized → leave alone
  const keepQuotes = (val, token) => {
    const q = /^["']/.test(val) ? val[0] : '';
    return q + token + q;
  };
  // key = value / key: value / "key": "value"
  const kv = (keys, token) => ({
    type: 'fn',
    re: new RegExp(`\\b((?:${keys})["']?\\s*[:=]\\s*)${VAL}`, 'gi'),
    fn: (m, pre, val) => (IS_TOKEN.test(pre) || IS_TOKEN.test(val) ? m : pre + keepQuotes(val, token)),
  });
  // --flag value / --flag=value
  const flag = (keys, token) => ({
    type: 'fn',
    re: new RegExp(`(?<=^|\\s)(--?(?:${keys})(?:=|\\s+))${VAL}`, 'gim'),
    fn: (m, pre, val) => (IS_TOKEN.test(val) ? m : pre + keepQuotes(val, token)),
  });

  const USER_KEYS = 'user(?:[_-]?name)?|login|uid|user[_-]?id|db[_-]?user|admin[_-]?user';
  const PASS_KEYS = 'pass(?:word|wd|phrase)?|pwd|secret|db[_-]?pass(?:word)?|admin[_-]?pass(?:word)?';

  const IPV6 = new RegExp('(?<![\\w:])(?:' + [
    '(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}',
    '(?:[0-9a-f]{1,4}:){1,7}:',
    '(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}',
    '(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}',
    '(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}',
    '(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}',
    '(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}',
    '[0-9a-f]{1,4}:(?::[0-9a-f]{1,4}){1,6}',
    '::(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}',
  ].join('|') + ')(?![\\w:])', 'gi');
  const OCTET = '(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)';
  const IPV4 = new RegExp(`(?<![\\d.])(?:${OCTET}\\.){3}${OCTET}(?![\\d]|\\.\\d)`, 'g');


  // ---- Domains / FQDNs -------------------------------------------------------
  const CC_TLDS = ('ac ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bm bn bo br bs bt bw by bz ' +
    'ca cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg er es et eu fi fj fk fm fo fr ' +
    'ga gb gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu id ie il im in io iq ir is it je jm jo jp ' +
    'ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc me mg mh ml mm mn mo mp mq mr mt mu mv ' +
    'mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pn pr pt pw qa re ro ru rw sa sb sc sd se sg ' +
    'si sk sl sm sn sr ss st su sv sx sy sz tc td tf tg th tj tk tl tm tn to tr tt tv tw tz ua ug uk us uy uz va vc ve ' +
    'vg vi vn vu wf ws ye yt za zm zw').split(' ');
  // left out on purpose (look like file extensions): cc md mk mp ms pl pm ps py rs sh so
  const G_TLDS = ('com net org edu gov mil int info biz pro mobi asia ' +
    'io dev app ai cloud tech online site website xyz top shop store blog news live page link click email ' +
    'agency solutions services systems network digital media group company global world today space host ' +
    'hosting security software tools zone club life inc ltd llc gmbh bank insurance health ' +
    'amsterdam berlin london paris nyc tokyo ' +
    'local localdomain internal intranet intra lan corp home arpa').split(' ');
  const TLDS = new Set([...CC_TLDS, ...G_TLDS]);
  // 2-label names with these endings are usually code (item.id, this.is, foo.to), so need 3+ labels
  const RISKY_2LABEL = new Set('id do is as to it in at no me so am st la my'.split(' '));

  const LABEL = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
  const BARE_FQDN = new RegExp(`(?<![\\w.-])((?:${LABEL}\\.)+([a-z]{2,63}))(?![\\w-]|\\.[a-z0-9])`, 'gi');
  const URL_HOST = /\b([a-z][\w+.-]*:\/\/)((?:[^\s\/@?#]*@)?)(\[[^\]\s]+\]|[^\s\/:?#@\]]+)/gi;
  const LOOKS_LIKE_IP = /^(?:\[.*\]|\d{1,3}(?:\.\d{1,3}){3})$/;

  function domainMapper(o) {
    const dummy = (o.fqdnDummy || 'example.com').trim().toLowerCase();
    const seen = new Map();
    const isDummy = (d) => d === dummy || d.endsWith('.' + dummy);
    return {
      reset: () => seen.clear(),
      map(name) {
        const key = name.toLowerCase().replace(/\.$/, '');
        if (isDummy(key) || key === 'localhost' || /^(?:USERNAME|PASSWD|IPADDR)$/i.test(key)) return null;
        if (!seen.has(key)) seen.set(key, o.fqdnNumbered ? `host${seen.size + 1}.${dummy}` : dummy);
        return seen.get(key);
      },
    };
  }

  function fqdnRules(o) {
    const dm = domainMapper(o);
    return [
      { // host part of any URL: https://anything.here/...
        type: 'fn', label: 'FQDN', reset: dm.reset, re: URL_HOST,
        fn: (m, scheme, userinfo, hostName) => {
          if (LOOKS_LIKE_IP.test(hostName) || !/[a-z]/i.test(hostName)) return m;
          const d = dm.map(hostName);
          return d ? scheme + userinfo + d : m;
        },
      },
      { // bare domains in text: server01.corp.acme.nl, john@acme.com
        type: 'fn', label: 'FQDN', re: BARE_FQDN,
        fn: (m, name, tld) => {
          tld = tld.toLowerCase();
          if (!TLDS.has(tld)) return m;
          if (name.split('.').length === 2 && RISKY_2LABEL.has(tld)) return m;
          return dm.map(name) || m;
        },
      },
    ];
  }

  function builtinRules(o) {
    const r = [];
    // scheme://user:pass@host
    if (o.detectUser || o.detectPass) {
      r.push({
        type: 'fn',
        re: /\b([a-z][\w+.-]*:\/\/)([^\s:@\/]+)(?::([^\s@\/]*))?@/gi,
        fn: (m, scheme, u, pw) =>
          scheme + (o.detectUser ? TOK.user : u) +
          (pw != null ? ':' + (o.detectPass ? TOK.pass : pw) : '') + '@',
      });
      // curl -u user:pass
      r.push({
        type: 'fn',
        re: /(?<=^|\s)(-u\s+|--user[=\s]+)(["']?)([^\s:"']+):([^\s"']+)\2/gim,
        fn: (m, pre, q, u, pw) =>
          pre + q + (o.detectUser ? TOK.user : u) + ':' + (o.detectPass ? TOK.pass : pw) + q,
      });
    }
    if (o.detectPass) r.push(kv(PASS_KEYS, TOK.pass), flag('password|passwd|pass', TOK.pass));
    if (o.detectUser) {
      r.push(kv(USER_KEYS, TOK.user), flag('user(?:name)?|login', TOK.user));
      // Windows: net use ... /user:name
      r.push({ type: 'regex', re: /(\/user:)([^\s"']+)/gi, replace: '$1' + TOK.user });
      // ssh/scp/sftp/rsync user@host
      r.push({
        type: 'fn',
        re: /\b((?:ssh|scp|sftp|rsync|mosh)\b[^\n@]*?\s)([\w.-]+)@/gi,
        fn: (m, pre) => pre + TOK.user + '@',
      });
    }
    if (o.detectFQDN) r.push(...fqdnRules(o));
    if (o.detectIP) {
      r.push({ type: 'regex', re: IPV6, replace: TOK.ip });
      r.push({ type: 'regex', re: IPV4, replace: TOK.ip });
    }
    return r;
  }
  const currentBuiltinOpts = () => ({
    detectIP: get('detectIP'), detectUser: get('detectUser'), detectPass: get('detectPass'),
    detectFQDN: get('detectFQDN'), fqdnDummy: get('fqdnDummy'), fqdnNumbered: get('fqdnNumbered'),
  });

  // Keyword rules first (your exact values win), then built-in detectors, then regex rules
  const orderRules = (dict, builtins) => [
    ...dict.filter((r) => r.type === 'literal'),
    ...builtins,
    ...dict.filter((r) => r.type !== 'literal'),
  ];

  let cache = { key: null, rules: [] };
  function getRules() {
    const text = get('rulesText');
    const opts = currentBuiltinOpts();
    const key = text + '\u0000' + JSON.stringify(opts);
    if (key !== cache.key) cache = { key, rules: orderRules(parseRules(text).rules, builtinRules(opts)) };
    return cache.rules;
  }

  const labelOf = (repl) => (repl || '').replace(/\$(\d+|&|<\w+>)/g, '').trim() || '(deleted)';
  const TOKENS = ['IPADDR', 'USERNAME', 'PASSWD'];
  const countIn = (str, tok) => str.split(tok).length - 1;

  function sanitize(input, rules = getRules()) {
    let text = input;
    let count = 0;
    const details = new Map(); // label → number of replacements
    const add = (label, n) => {
      if (n <= 0) return;
      count += n;
      details.set(label, (details.get(label) || 0) + n);
    };
    for (const r of rules) if (r.reset) r.reset();
    for (const r of rules) {
      if (r.type === 'literal') {
        const parts = text.split(r.find);
        if (parts.length > 1) {
          add(labelOf(r.replace), parts.length - 1);
          text = parts.join(r.replace);
        }
      } else if (r.type === 'fn') {
        text = text.replace(r.re, (...args) => {
          const out = r.fn(...args);
          if (out !== args[0] && r.label) add(r.label, 1);
          else if (out !== args[0]) {
            for (const t of TOKENS) add(t, countIn(out, t) - countIn(args[0], t));
          }
          return out;
        });
      } else {
        r.re.lastIndex = 0;
        const m = text.match(r.re);
        if (m) {
          add(labelOf(r.replace), m.length);
          text = text.replace(r.re, r.replace);
        }
      }
    }
    return { text, count, details };
  }

  // ---------------------------------------------------------------------------
  // Clipboard hooks
  // ---------------------------------------------------------------------------
  const TEXT_INPUT = /^(text|search|url|tel|email|)$/i;

  function textField(el) {
    if (!el) return null;
    if (el.tagName === 'TEXTAREA') return el;
    if (el.tagName === 'INPUT' && TEXT_INPUT.test(el.type)) return el;
    return null;
  }

  function insertText(target, text) {
    // execCommand keeps the undo stack and fires input events editors listen to
    if (document.execCommand('insertText', false, text)) return true;
    const field = textField(target);
    if (field) {
      field.setRangeText(text, field.selectionStart, field.selectionEnd, 'end');
      field.dispatchEvent(new Event('input', { bubbles: true }));
      return true;
    }
    return false;
  }

  function onPaste(e) {
    if (!enabledHere() || !e.clipboardData) return;

    const original = e.clipboardData.getData('text/plain');
    if (!original) return;

    const { text, count, details } = sanitize(original);
    if (!count || text === original) return; // untouched → native paste

    const target = e.composedPath()[0];
    e.preventDefault();
    e.stopImmediatePropagation(); // stop rich editors from inserting the original
    if (insertText(target, text)) warn(count, details);
  }

  window.addEventListener('paste', onPaste, true);

  // ---------------------------------------------------------------------------
  // Tiny DOM helpers (no innerHTML → works on Trusted-Types sites)
  // ---------------------------------------------------------------------------
  function h(tag, props = {}, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
      if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else if (k in el) el[k] = v;
      else el.setAttribute(k, v);
    }
    for (const c of children.flat()) if (c != null) el.append(c);
    return el;
  }

  function shadowHost(css) {
    const hostEl = document.createElement('cps-sanitizer');
    const root = hostEl.attachShadow({ mode: 'open' });
    try {
      const sheet = new CSSStyleSheet();
      sheet.replaceSync(css);
      root.adoptedStyleSheets = [sheet];
    } catch {
      root.append(h('style', { textContent: css }));
    }
    (document.body || document.documentElement).append(hostEl);
    return { hostEl, root };
  }

  // ---------------------------------------------------------------------------
  // Toast
  // ---------------------------------------------------------------------------
  const TOAST_CSS = `
    .t { position: fixed; z-index: 2147483647; right: 16px; bottom: 16px;
      font: 13px/1.4 system-ui, sans-serif; color: #fff; background: #1f2937;
      padding: 8px 12px; border-radius: 8px; box-shadow: 0 4px 16px rgba(0,0,0,.25);
      opacity: 0; transform: translateY(6px); transition: opacity .2s, transform .2s; }
    .t.show { opacity: 1; transform: none; }`;
  let toastEl = null;
  let toastTimer = 0;

  function toast(msg) {
    if (!get('notify')) return;
    if (!toastEl || !toastEl.isConnected) {
      const { root } = shadowHost(TOAST_CSS);
      toastEl = h('div', { className: 't' });
      root.append(toastEl);
    }
    toastEl.textContent = '🧼 ' + msg;
    requestAnimationFrame(() => toastEl.classList.add('show'));
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toastEl.classList.remove('show'), 2000);
  }

  // ---------------------------------------------------------------------------
  // Red warning popup (shown when a paste was changed)
  // ---------------------------------------------------------------------------
  const WARN_MS = 8000;
  const WARN_CSS = `
    .w { position: fixed; z-index: 2147483647; top: 16px; left: 50%;
      transform: translate(-50%, -12px); opacity: 0; transition: opacity .2s, transform .2s;
      width: min(420px, 92vw); font: 14px/1.45 system-ui, sans-serif; color: #fff;
      background: #b91c1c; border: 2px solid #7f1d1d; border-radius: 10px;
      box-shadow: 0 10px 30px rgba(127,29,29,.45); padding: 12px 40px 12px 14px; }
    .w.show { opacity: 1; transform: translate(-50%, 0); }
    .title { font-weight: 700; font-size: 15px; margin-bottom: 4px; }
    ul { margin: 6px 0 0; padding: 0; list-style: none; display: flex; flex-wrap: wrap; gap: 6px; }
    li { background: rgba(0,0,0,.25); border-radius: 6px; padding: 2px 8px;
      font: 12.5px/1.5 ui-monospace, Menlo, Consolas, monospace; }
    .x { position: absolute; top: 6px; right: 8px; border: 0; background: none; color: #fff;
      font-size: 20px; line-height: 1; cursor: pointer; opacity: .85; padding: 4px; }
    .x:hover { opacity: 1; }
    .bar { position: absolute; left: 0; bottom: 0; height: 3px; background: rgba(255,255,255,.6);
      border-radius: 0 0 0 8px; width: 100%; transform-origin: left; }
    .w:hover .bar { animation-play-state: paused; }
    @keyframes shrink { from { transform: scaleX(1); } to { transform: scaleX(0); } }`;
  let warnHost = null;

  function warn(count, details) {
    if (!get('notify')) return;
    if (warnHost) warnHost.remove();
    const { hostEl, root } = shadowHost(WARN_CSS);
    warnHost = hostEl;

    const close = () => {
      box.classList.remove('show');
      setTimeout(() => hostEl.remove(), 250);
      if (warnHost === hostEl) warnHost = null;
    };
    const bar = h('div', { className: 'bar' });
    bar.style.animation = `shrink ${WARN_MS}ms linear forwards`;
    bar.addEventListener('animationend', close); // pauses while hovered

    const box = h('div', { className: 'w', role: 'alert' },
      h('div', { className: 'title' }, '⚠️ Sensitive data replaced on paste'),
      h('div', {}, `${count} replacement${count === 1 ? '' : 's'} made. Check the pasted text before sending.`),
      h('ul', {}, [...details].map(([label, n]) => h('li', {}, `${label} ×${n}`))),
      h('button', { className: 'x', title: 'Dismiss', onclick: close }, '×'),
      bar,
    );
    root.append(box);
    requestAnimationFrame(() => box.classList.add('show'));
  }

  // ---------------------------------------------------------------------------
  // Settings panel
  // ---------------------------------------------------------------------------
  const PANEL_CSS = `
    * { box-sizing: border-box; }
    .bg { position: fixed; inset: 0; z-index: 2147483647; background: rgba(0,0,0,.45);
      display: flex; align-items: center; justify-content: center;
      font: 14px/1.45 system-ui, sans-serif; color: #111827; }
    .p { background: #fff; width: min(860px, 94vw); max-height: 92vh; overflow: auto;
      border-radius: 12px; padding: 20px 22px; box-shadow: 0 20px 60px rgba(0,0,0,.35); }
    h2 { margin: 0 0 12px; font-size: 18px; }
    h3 { margin: 16px 0 6px; font-size: 13px; text-transform: uppercase; letter-spacing: .04em; color: #6b7280; }
    .opts { display: flex; flex-wrap: wrap; gap: 6px 18px; }
    label { display: inline-flex; gap: 6px; align-items: center; cursor: pointer; }
    textarea { width: 100%; font: 12.5px/1.5 ui-monospace, Menlo, Consolas, monospace;
      border: 1px solid #d1d5db; border-radius: 8px; padding: 8px 10px; resize: vertical; color: #111827; background: #fff; }
    .inline { display: inline-flex; gap: 6px; align-items: center; }
    input[type=text] { font: 12.5px ui-monospace, Menlo, Consolas, monospace; padding: 3px 7px; width: 170px;
      border: 1px solid #d1d5db; border-radius: 6px; color: #111827; background: #fff; }
    input[type=text]:focus, textarea:focus { outline: 2px solid #2563eb; outline-offset: -1px; }
    .rules { height: 240px; }
    .err { color: #b91c1c; font-size: 12.5px; white-space: pre-wrap; min-height: 1em; margin-top: 4px; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
    .grid textarea { height: 110px; }
    .muted { color: #6b7280; font-size: 12.5px; }
    .row { display: flex; gap: 8px; justify-content: flex-end; margin-top: 16px; }
    button { font: inherit; border: 1px solid #d1d5db; background: #f9fafb; color: #111827;
      border-radius: 8px; padding: 6px 14px; cursor: pointer; }
    button:hover { background: #f3f4f6; }
    button.primary { background: #2563eb; border-color: #2563eb; color: #fff; }
    button.primary:hover { background: #1d4ed8; }
    .spacer { flex: 1; }`;

  function openSettings() {
    if (document.querySelector('cps-sanitizer[data-panel]')) return;
    const { hostEl, root } = shadowHost(PANEL_CSS);
    hostEl.dataset.panel = '1';
    const close = () => hostEl.remove();

    const rulesTa = h('textarea', { className: 'rules', spellcheck: false, value: get('rulesText') });
    const errBox = h('div', { className: 'err' });
    const testIn = h('textarea', { placeholder: 'Paste sample text here…', spellcheck: false });
    const testOut = h('textarea', { readOnly: true, placeholder: 'Sanitized result' });
    const testInfo = h('div', { className: 'muted' });

    const cb = (key, labelText, checked = get(key)) => {
      const input = h('input', { type: 'checkbox', checked });
      return { input, el: h('label', {}, input, labelText) };
    };
    const notifyCb = cb('notify', 'Show red warning when something is replaced');
    const ipCb = cb('detectIP', 'IP addresses → IPADDR');
    const userCb = cb('detectUser', 'Usernames → USERNAME');
    const passCb = cb('detectPass', 'Passwords → PASSWD');
    const fqdnCb = cb('detectFQDN', 'Domains / FQDNs →');
    const fqdnIn = h('input', { type: 'text', value: get('fqdnDummy'), spellcheck: false, placeholder: 'example.com' });
    const numCb = cb('fqdnNumbered', 'Number different domains (host1, host2, …)');
    const siteCb = cb(null, `Enabled on ${host || 'this page'}`, enabledHere());

    function refresh() {
      const parsed = parseRules(rulesTa.value);
      const errors = parsed.errors;
      const rules = orderRules(parsed.rules, builtinRules({
        detectIP: ipCb.input.checked, detectUser: userCb.input.checked, detectPass: passCb.input.checked,
        detectFQDN: fqdnCb.input.checked, fqdnDummy: fqdnIn.value, fqdnNumbered: numCb.input.checked,
      }));
      errBox.textContent = errors.join('\n');
      const { text, count } = sanitize(testIn.value, rules);
      testOut.value = text;
      testInfo.textContent = testIn.value
        ? `${rules.length} rule(s) · ${count} replacement(s)`
        : `${parsed.rules.length} dictionary rule(s) + built-in detectors`;
    }
    rulesTa.addEventListener('input', refresh);
    for (const c of [ipCb, userCb, passCb, fqdnCb, numCb]) c.input.addEventListener('change', refresh);
    fqdnIn.addEventListener('input', refresh);
    testIn.addEventListener('input', refresh);

    function save() {
      set('rulesText', rulesTa.value);
      set('notify', notifyCb.input.checked);
      set('detectIP', ipCb.input.checked);
      set('detectUser', userCb.input.checked);
      set('detectPass', passCb.input.checked);
      set('detectFQDN', fqdnCb.input.checked);
      set('fqdnDummy', fqdnIn.value.trim() || 'example.com');
      set('fqdnNumbered', numCb.input.checked);
      const hosts = new Set(get('disabledHosts'));
      siteCb.input.checked ? hosts.delete(host) : hosts.add(host);
      set('disabledHosts', [...hosts]);
      close();
      toast('Settings saved');
    }

    const panel = h('div', { className: 'p' },
      h('h2', {}, '🧼 Paste Sanitizer'),
      h('div', { className: 'opts' }, notifyCb.el, siteCb.el),
      h('h3', {}, 'Built-in detectors'),
      h('div', { className: 'opts' }, ipCb.el, userCb.el, passCb.el),
      h('div', { className: 'opts', style: 'margin-top:6px' },
        h('span', { className: 'inline' }, fqdnCb.el, fqdnIn), numCb.el),
      h('h3', {}, 'Dictionary'),
      rulesTa,
      errBox,
      h('h3', {}, 'Try it'),
      h('div', { className: 'grid' }, testIn, testOut),
      testInfo,
      h('div', { className: 'row' },
        h('button', { onclick: () => { rulesTa.value = DEFAULT_RULES; refresh(); } }, 'Load examples'),
        h('button', { onclick: () => { navigator.clipboard?.writeText(testOut.value); } }, 'Copy result'),
        h('span', { className: 'spacer' }),
        h('button', { onclick: close }, 'Cancel'),
        h('button', { className: 'primary', onclick: save }, 'Save'),
      ),
    );

    const bg = h('div', { className: 'bg', onmousedown: (e) => { if (e.target === bg) close(); } }, panel);
    // keep page shortcuts from firing while typing in the panel
    for (const t of ['keydown', 'keyup', 'keypress', 'copy', 'cut', 'paste']) {
      bg.addEventListener(t, (e) => {
        if (t === 'keydown' && e.key === 'Escape') close();
        e.stopPropagation();
      });
    }
    root.append(bg);
    refresh();
    rulesTa.focus();
  }

  // ---------------------------------------------------------------------------
  // Menu (top frame only, so commands don't appear once per iframe)
  // ---------------------------------------------------------------------------
  if (window.top === window) {
    GM_registerMenuCommand('⚙️ Edit dictionary & settings', openSettings);
    GM_registerMenuCommand(enabledHere() ? '⏸ Disable on this site' : '▶️ Enable on this site', () => {
      const hosts = new Set(get('disabledHosts'));
      hosts.has(host) ? hosts.delete(host) : hosts.add(host);
      set('disabledHosts', [...hosts]);
      location.reload();
    });
  }
})();
