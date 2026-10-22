/* Mnemonica · sincronizzazione e backup tramite un gruppo Telegram privato.
   I dati vengono cifrati nel browser con la tua password prima di essere inviati. */
(function () {
  var COLS = { link: 'mnemonica-link-metod', pal: 'mnemonica-palazzi', flash: 'mnemonica-flash', fon: 'mnemonica-fonetica' };
  var MK = 'mnemonica-sync-meta', BK = 'mnemonica-sync-backup', enc = new TextEncoder(), dec = new TextDecoder();
  var meta, busy = false, timer = null, statusEl = null;

  function load() {
    try { meta = JSON.parse(localStorage.getItem(MK)) || {}; } catch (e) { meta = {}; }
    meta.dev = meta.dev || Math.random().toString(36).slice(2, 8);
    meta.base = meta.base || {}; meta.tomb = meta.tomb || {};
  }
  function save() { try { localStorage.setItem(MK, JSON.stringify(meta)); } catch (e) {} }
  function hash(s) { var x = 5381; for (var i = 0; i < s.length; i++) x = ((x << 5) + x + s.charCodeAt(i)) | 0; return x; }
  function say(t) { if (statusEl) statusEl.textContent = t; }

  // --- lettura e scrittura dei dati locali come mappe id -> elemento
  function readLocal() {
    var L = {};
    Object.keys(COLS).forEach(function (c) {
      var raw = null, m = {};
      try { raw = JSON.parse(localStorage.getItem(COLS[c])); } catch (e) {}
      if (Array.isArray(raw)) raw.forEach(function (it) { if (it && it.id) m[it.id] = it; });
      else if (raw && typeof raw === 'object') Object.keys(raw).forEach(function (k) { m[k] = raw[k]; });
      L[c] = m;
    });
    return L;
  }
  function writeLocal(out, order) {
    var changed = false;
    Object.keys(COLS).forEach(function (c) {
      var m = out[c], val;
      if (c === 'fon') { val = {}; Object.keys(m).forEach(function (k) { val[k] = m[k]; }); }
      else {
        var ids = (order[c] || []).filter(function (i) { return m[i]; });
        Object.keys(m).forEach(function (i) { if (ids.indexOf(i) < 0) ids.unshift(i); });
        val = ids.map(function (i) { return m[i]; });
      }
      var s = JSON.stringify(val), old = localStorage.getItem(COLS[c]);
      if ((old || (c === 'fon' ? '{}' : '[]')) !== s) { localStorage.setItem(COLS[c], s); changed = true; }
    });
    return changed;
  }

  // --- data dell'ultima modifica di ogni elemento, ed eliminazioni ricordate
  function stamp() {
    var L = readLocal(), now = Date.now(), first = !meta.init, any = false;
    Object.keys(COLS).forEach(function (c) {
      var base = meta.base[c] = meta.base[c] || {}, tomb = meta.tomb[c] = meta.tomb[c] || {};
      Object.keys(L[c]).forEach(function (id) {
        var h = hash(JSON.stringify(L[c][id])), b = base[id];
        if (!b) { base[id] = { h: h, u: first ? 0 : now }; if (!first) any = true; }
        else if (b.h !== h) { b.h = h; b.u = now; any = true; }
        if (tomb[id] && base[id].u > tomb[id]) delete tomb[id];
      });
      Object.keys(base).forEach(function (id) { if (!L[c][id]) { tomb[id] = now; delete base[id]; any = true; } });
      Object.keys(tomb).forEach(function (id) { if (now - tomb[id] > 90 * 864e5) delete tomb[id]; });
    });
    meta.init = true;
    if (any) meta.dirty = true;
    save();
    return L;
  }

  function snapshot() {
    var L = readLocal(), items = {};
    Object.keys(COLS).forEach(function (c) {
      items[c] = {};
      Object.keys(L[c]).forEach(function (id) { items[c][id] = { v: L[c][id], u: (meta.base[c][id] || {}).u || 0 }; });
    });
    return { items: items, tomb: meta.tomb };
  }

  // --- unione: vince la modifica più recente; un'eliminazione più recente cancella ovunque
  function merge(R) {
    var L = readLocal(), out = {}, order = {};
    Object.keys(COLS).forEach(function (c) {
      var base = meta.base[c] = meta.base[c] || {}, tomb = meta.tomb[c] = meta.tomb[c] || {};
      var ri = (R.items || {})[c] || {}, rt = (R.tomb || {})[c] || {}, ids = {};
      order[c] = Object.keys(L[c]);
      Object.keys(L[c]).concat(Object.keys(ri)).forEach(function (i) { ids[i] = 1; });
      out[c] = {};
      Object.keys(ids).forEach(function (id) {
        var l = L[c][id] ? { v: L[c][id], u: (base[id] || {}).u || 0 } : null, r = ri[id] || null;
        var best = !l ? r : !r ? l : (r.u > l.u ? r : l), t = Math.max(tomb[id] || 0, rt[id] || 0);
        if (best && t > 0 && t >= best.u) { tomb[id] = t; delete base[id]; }
        else if (best) { out[c][id] = best.v; base[id] = { h: hash(JSON.stringify(best.v)), u: best.u }; delete tomb[id]; }
      });
      Object.keys(rt).forEach(function (id) { if (!ids[id] || !out[c][id]) { if (!out[c][id]) tomb[id] = Math.max(tomb[id] || 0, rt[id]); } });
    });
    return writeLocal(out, order);
  }

  // --- cifratura con la password
  function b2k(pwd, salt) {
    return crypto.subtle.importKey('raw', enc.encode(pwd), 'PBKDF2', false, ['deriveKey']).then(function (k) {
      return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' }, k, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    });
  }
  function seal(obj, pwd) {
    var salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
    return b2k(pwd, salt).then(function (k) { return crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, k, enc.encode(JSON.stringify(obj))); })
      .then(function (ct) { return new Blob([salt, iv, ct]); });
  }
  function open(buf, pwd) {
    var u = new Uint8Array(buf);
    return b2k(pwd, u.slice(0, 16)).then(function (k) { return crypto.subtle.decrypt({ name: 'AES-GCM', iv: u.slice(16, 28) }, k, u.slice(28)); })
      .then(function (pt) { return JSON.parse(dec.decode(pt)); });
  }

  // --- Telegram
  function api(method, body, form) {
    var c = meta.cfg;
    return fetch('https://api.telegram.org/bot' + c.t + '/' + method, form
      ? { method: 'POST', body: form }
      : { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) })
      .then(function (r) { return r.json(); })
      .then(function (j) { if (!j.ok) throw new Error(j.description || 'Errore Telegram'); return j.result; });
  }
  function pinned() {
    return api('getChat', { chat_id: meta.cfg.c }).then(function (ch) {
      var m = ch.pinned_message, p = m && m.caption ? m.caption.split('|') : null;
      return p && p[0] === 'mnemonica' && m.document ? { dev: p[1], ts: p[2], fid: m.document.file_id } : null;
    });
  }
  function push() {
    var ts = String(Date.now());
    return seal(snapshot(), meta.cfg.p).then(function (blob) {
      var f = new FormData();
      f.append('chat_id', meta.cfg.c); f.append('caption', 'mnemonica|' + meta.dev + '|' + ts);
      f.append('document', blob, 'mnemonica-backup.bin');
      return api('sendDocument', null, f);
    }).then(function (m) {
      return api('pinChatMessage', { chat_id: meta.cfg.c, message_id: m.message_id, disable_notification: true });
    }).then(function () { meta.seen = ts; meta.dirty = false; save(); });
  }
  function pull(pin) {
    return api('getFile', { file_id: pin.fid }).then(function (f) {
      return fetch('https://api.telegram.org/file/bot' + meta.cfg.t + '/' + f.file_path);
    }).then(function (r) { return r.arrayBuffer(); }).then(function (b) { return open(b, meta.cfg.p); })
      .then(function (R) {
        try { localStorage.setItem(BK, JSON.stringify(readLocal())); }
        catch (e) { throw new Error('Spazio insufficiente per la copia di sicurezza: unione annullata.'); }
        var changed = merge(R);
        meta.seen = pin.ts; meta.dirty = true; save();
        return changed;
      });
  }

  // --- sincronizzazione completa: scarica se c'è una copia più recente di un altro dispositivo, poi invia
  function run(manual) {
    if (busy || !meta.cfg) return Promise.resolve();
    busy = true; say('Sincronizzazione in corso…');
    stamp();
    return pinned().then(function (pin) {
      if (pin && pin.dev !== meta.dev && pin.ts !== meta.seen) {
        return pull(pin).then(function (changed) { if (changed) { say('Dati uniti, ricarico la pagina…'); setTimeout(function () { location.reload(); }, 600); return 'reload'; } });
      }
    }).then(function (r) {
      if (r === 'reload') return;
      if (meta.dirty || manual) return push().then(function () { say('Copia salvata su Telegram.'); });
      say('Tutto aggiornato.');
    }).catch(function (e) {
      say(e && e.name === 'OperationError' ? 'Password errata o copia non leggibile.' : 'Errore: ' + (e.message || e));
    }).then(function () { busy = false; });
  }

  // --- pannello
  function ui() {
    var css = document.createElement('style');
    css.textContent = '#mns{position:fixed;right:12px;bottom:12px;z-index:90;font:14px/1.4 system-ui,sans-serif}' +
      '#mns>button{width:44px;height:44px;border-radius:50%;border:1px solid #cdd3df;background:#f8f9fb;color:#1f7a7a;font-size:20px;cursor:pointer}' +
      '#mns .p{position:absolute;right:0;bottom:54px;width:min(320px,calc(100vw - 24px));background:#fff;border:1px solid #cdd3df;border-radius:14px;padding:14px;box-shadow:0 6px 24px rgba(27,37,64,.18);color:#1b2540}' +
      '#mns .p[hidden]{display:none}#mns label{display:block;font-weight:600;margin-top:8px}' +
      '#mns input{width:100%;font:inherit;padding:8px 10px;border:1px solid #cdd3df;border-radius:8px;margin-top:3px}' +
      '#mns .p button{font:inherit;font-weight:600;padding:8px 12px;border-radius:10px;border:1px solid #cdd3df;background:#f8f9fb;cursor:pointer;margin:10px 6px 0 0}' +
      '#mns .p button.go{background:#1f7a7a;border-color:#1f7a7a;color:#fff}#mns .st{margin-top:10px;color:#5b6580}';
    document.head.appendChild(css);
    var box = document.createElement('div');
    box.id = 'mns';
    box.innerHTML = '<button type="button" aria-label="Sincronizzazione e backup" aria-expanded="false">⟳</button>' +
      '<div class="p" hidden role="dialog" aria-label="Sincronizzazione"><strong>Backup su Telegram</strong>' +
      '<label for="mnt">Token del bot</label><input id="mnt" type="password" autocomplete="off">' +
      '<label for="mnc">ID del gruppo</label><input id="mnc" type="text" autocomplete="off">' +
      '<label for="mnp">Password di cifratura</label><input id="mnp" type="password" autocomplete="off">' +
      '<div><button type="button" class="go" data-a="link">Collega</button><button type="button" data-a="now">Sincronizza ora</button><button type="button" data-a="off">Scollega</button></div>' +
      '<div class="st" aria-live="polite"></div><div class="st">Dispositivo: <span id="mnd"></span></div></div>';
    document.body.appendChild(box);
    statusEl = box.querySelector('.p .st');
    var pan = box.querySelector('.p'), tog = box.querySelector('#mns>button');
    box.querySelector('#mnd').textContent = meta.dev;
    function fill() {
      var c = meta.cfg || {};
      box.querySelector('#mnt').value = c.t || ''; box.querySelector('#mnc').value = c.c || ''; box.querySelector('#mnp').value = c.p || '';
      say(meta.cfg ? 'Collegato.' : 'Non collegato.');
    }
    tog.addEventListener('click', function () { pan.hidden = !pan.hidden; tog.setAttribute('aria-expanded', String(!pan.hidden)); if (!pan.hidden) fill(); });
    pan.addEventListener('click', function (ev) {
      var a = ev.target.getAttribute && ev.target.getAttribute('data-a');
      if (a === 'link') {
        var t = box.querySelector('#mnt').value.trim(), c = box.querySelector('#mnc').value.trim(), p = box.querySelector('#mnp').value;
        if (!t || !c || !p) { say('Compila token, ID del gruppo e password.'); return; }
        meta.cfg = { t: t, c: c, p: p }; save(); run(true);
      } else if (a === 'now') run(true);
      else if (a === 'off') { delete meta.cfg; save(); fill(); }
    });
  }

  function start() {
    load(); stamp(); ui();
    if (meta.cfg) run(false);
    setInterval(function () {
      if (!meta.cfg) return;
      stamp();
      if (meta.dirty && !busy) { clearTimeout(timer); timer = setTimeout(function () { run(false); }, 6000); }
    }, 4000);
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();
})();
