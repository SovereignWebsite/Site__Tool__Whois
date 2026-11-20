// Whois over RDAP, in the browser. IANA's bootstrap files say which registry to ask;
// the registry answers in JSON. No server, no cookies, no storage. sites.b, 20 Nov 2026. Apache-2.0.
'use strict';
const $ = (s) => document.querySelector(s);
const IANA = 'https://data.iana.org/rdap/';
const boot = {};
async function bootstrap(kind) {
  if (!boot[kind]) boot[kind] = fetch(IANA + kind + '.json', { credentials: 'omit' }).then((r) => {
    if (!r.ok) throw new Error('IANA did not answer (' + r.status + ').'); return r.json(); });
  return (await boot[kind]).services;
}
const pick = (urls) => urls.find((u) => u.startsWith('https:')) || urls[0];
const join = (base, path) => base.replace(/\/?$/, '/') + path;

// ---------- what was typed ----------
function classify(raw) {
  let s = raw.trim();
  if (!s) return null;
  if (/^as\d+$/i.test(s)) return { kind: 'asn', q: s.slice(2) };
  if (/^\d+$/.test(s) && Number(s) < 4294967296 && !/^\d+\.\d/.test(s)) return { kind: 'asn', q: s };
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').replace(/^[^@/]*@/, '');
  const v6 = s.match(/^\[?([0-9a-f:.]*:[0-9a-f:.]*)\]?(?:%.*)?(?:\/\d+)?$/i);
  if (v6 && v6[1].includes(':')) return { kind: 'ipv6', q: v6[1].toLowerCase() };
  s = s.split(/[/?#]/)[0].replace(/:\d+$/, '').replace(/\.$/, '');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) {
    if (s.split('.').some((o) => Number(o) > 255)) throw new Error('That is not a valid IPv4 address.');
    return { kind: 'ipv4', q: s };
  }
  let host;
  try { host = new URL('http://' + s).hostname; } catch { throw new Error('That does not look like a domain, an IP address or an AS number.'); }
  if (!host.includes('.') || !/^[a-z0-9.-]+$/.test(host)) throw new Error('That does not look like a domain, an IP address or an AS number.');
  return { kind: 'domain', q: host };
}

// ---------- which registry ----------
function v4num(ip) { return ip.split('.').reduce((n, o) => n * 256n + BigInt(o), 0n); }
function v6num(ip) {
  let [h, t] = ip.split('::');
  const part = (x) => (x ? x.split(':') : []);
  let head = part(h), tail = t === undefined ? [] : part(t);
  const last = (tail.length ? tail : head).slice(-1)[0] || '';
  if (last.includes('.')) { // embedded IPv4
    const n = v4num(last); const arr = tail.length ? tail : head; arr.pop();
    arr.push((n >> 16n).toString(16), (n & 0xffffn).toString(16));
  }
  const fill = t === undefined ? [] : Array(8 - head.length - tail.length).fill('0');
  const all = [...head, ...fill, ...tail];
  if (all.length !== 8 || all.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) throw new Error('That is not a valid IPv6 address.');
  return all.reduce((n, g) => n * 65536n + BigInt('0x' + g), 0n);
}
function inCidr(num, cidr, bits) {
  const [base, len] = cidr.split('/');
  const b = bits === 32 ? v4num(base.split('.').concat(['0', '0', '0']).slice(0, 4).join('.')) : v6num(base);
  const shift = BigInt(bits - Number(len));
  return (num >> shift) === (b >> shift);
}
async function registryFor(t) {
  if (t.kind === 'domain') {
    const svc = await bootstrap('dns'); const labels = t.q.split('.');
    for (let i = 0; i < labels.length; i++) {
      const tld = labels.slice(i).join('.');
      const hit = svc.find(([tlds]) => tlds.includes(tld));
      if (hit) return { base: pick(hit[1]), tld };
    }
    return null;
  }
  if (t.kind === 'asn') {
    const n = Number(t.q); const svc = await bootstrap('asn');
    const hit = svc.find(([ranges]) => ranges.some((r) => { const [a, b = a] = r.split('-').map(Number); return n >= a && n <= b; }));
    return hit && { base: pick(hit[1]) };
  }
  const bits = t.kind === 'ipv4' ? 32 : 128;
  const num = bits === 32 ? v4num(t.q) : v6num(t.q);
  const svc = await bootstrap(t.kind);
  let best = null, bestLen = -1;
  for (const [cidrs, urls] of svc) for (const c of cidrs) {
    const len = Number(c.split('/')[1]);
    if (len > bestLen && inCidr(num, c, bits)) { best = urls; bestLen = len; }
  }
  return best && { base: pick(best) };
}

async function getJSON(url) {
  let r;
  try { r = await fetch(url, { credentials: 'omit', headers: { Accept: 'application/rdap+json, application/json' } }); }
  catch { const e = new Error('The registry did not answer this browser. It may not allow lookups from web pages.'); e.network = true; throw e; }
  if (r.status === 404) { const e = new Error('The registry has no record of this.'); e.notFound = true; throw e; }
  if (r.status === 429) throw new Error('The registry asks us to slow down. Try again in a minute.');
  if (!r.ok) throw new Error('The registry answered with an error (' + r.status + ').');
  return { url: r.url || url, json: await r.json() };
}

async function lookup(t) {
  const reg = await registryFor(t);
  if (!reg) {
    if (t.kind !== 'domain') throw new Error('IANA lists no registry for this.');
    const tld = t.q.split('.').pop();
    const e = new Error('The registry for .' + tld + ' does not offer RDAP, so there is no open record to read here. ');
    e.link = { href: 'https://www.iana.org/domains/root/db/' + encodeURIComponent(tld) + '.html', text: 'IANA\'s page for .' + tld + ' names its registry and lookup.' };
    throw e;
  }
  if (t.kind === 'domain') {
    // Ask for the name; if the registry does not know a subdomain, step up to its parent.
    let name = t.q; const min = reg.tld.split('.').length + 1;
    for (;;) {
      try { return { t, name, ...(await getJSON(join(reg.base, 'domain/' + name))) }; }
      catch (e) {
        if (!e.notFound || name.split('.').length <= min) throw e;
        name = name.split('.').slice(1).join('.');
      }
    }
  }
  const path = t.kind === 'asn' ? 'autnum/' + t.q : 'ip/' + t.q;
  return { t, name: t.kind === 'asn' ? 'AS' + t.q : t.q, ...(await getJSON(join(reg.base, path))) };
}

// ---------- reading the record ----------
function vcard(ent) {
  const out = {}; const rows = (ent.vcardArray && ent.vcardArray[1]) || [];
  for (const [k, params, , v] of rows) {
    const val = Array.isArray(v) ? v.flat().filter(Boolean).join(', ') : String(v || '');
    if (k === 'adr' && params && params.label) out.adr = params.label.replace(/\n/g, ', ');
    else if (k === 'fn' || k === 'org' || k === 'email' || k === 'tel' || k === 'adr') if (val && !out[k]) out[k] = val;
  }
  return out;
}
function entities(list, acc = []) {
  for (const e of list || []) { acc.push(e); entities(e.entities, acc); }
  return acc;
}
const ROLE = { registrant: 'Holder', registrar: 'Registrar', administrative: 'Administrative contact', technical: 'Technical contact', abuse: 'Abuse contact', billing: 'Billing contact', reseller: 'Reseller', sponsor: 'Sponsor', noc: 'Network operations' };
const EVENT = { registration: 'Registered', expiration: 'Expires', 'last changed': 'Last changed', 'last update of RDAP database': 'Record read', transfer: 'Last transfer' };
const date = (s) => { const d = new Date(s); return isNaN(d) ? s : d.toISOString().slice(0, 10) + ' (' + d.toUTCString().slice(5, 16) + ')'; };

function summarise(res) {
  const j = res.json, rows = [];
  const add = (k, v) => { if (v !== undefined && v !== null && v !== '' && !(Array.isArray(v) && !v.length)) rows.push([k, v]); };
  if (res.t.kind === 'domain') {
    add('Domain', (j.ldhName || res.name).toLowerCase() + (j.unicodeName && j.unicodeName !== j.ldhName ? ' (' + j.unicodeName + ')' : ''));
    if (res.name !== res.t.q) add('You asked for', res.t.q + ', which is part of this domain');
  } else if (res.t.kind === 'asn') {
    add('AS number', j.startAutnum && j.endAutnum && j.startAutnum !== j.endAutnum ? 'AS' + j.startAutnum + ' to AS' + j.endAutnum : 'AS' + (j.startAutnum || res.t.q));
    add('Name', j.name);
  } else {
    add('Range', j.startAddress && j.endAddress ? j.startAddress + ' to ' + j.endAddress : undefined);
    add('Prefix', (j.cidr0_cidrs || []).map((c) => (c.v4prefix || c.v6prefix) + '/' + c.length).join(', '));
    add('Network name', j.name);
    add('Type', j.type);
  }
  add('Handle', j.handle);
  add('Country', j.country);
  const ents = entities(j.entities);
  const registrar = ents.find((e) => (e.roles || []).includes('registrar'));
  if (registrar) {
    const v = vcard(registrar); const id = (registrar.publicIds || []).find((p) => /iana/i.test(p.type));
    add('Registrar', (v.fn || v.org || registrar.handle || '') + (id ? ' (IANA ' + id.identifier + ')' : ''));
  }
  for (const ev of j.events || []) if (EVENT[ev.eventAction] && ev.eventAction !== 'last update of RDAP database') add(EVENT[ev.eventAction], date(ev.eventDate));
  add('Status', (j.status || []).join(', '));
  add('Name servers', (j.nameservers || []).map((n) => (n.ldhName || '').toLowerCase()).filter(Boolean).join(', '));
  if (j.secureDNS) add('DNSSEC', j.secureDNS.delegationSigned ? 'signed' : 'not signed');
  return { rows, ents };
}

function contactCards(ents) {
  const frag = document.createDocumentFragment(); const seen = new Set();
  for (const e of ents) {
    const roles = (e.roles || []).filter((r) => ROLE[r]); if (!roles.length) continue;
    const v = vcard(e); const key = roles.join() + JSON.stringify(v); if (seen.has(key)) continue; seen.add(key);
    const card = document.createElement('div'); card.className = 'card';
    const h = document.createElement('h3'); h.textContent = roles.map((r) => ROLE[r]).join(', '); card.append(h);
    const lines = [v.fn, v.org && v.org !== v.fn ? v.org : '', v.adr, v.email, v.tel].filter(Boolean);
    const redacted = (e.remarks || []).some((r) => /redact/i.test((r.title || '') + (r.description || []).join(' ')));
    if (!lines.length) lines.push(redacted ? 'Details redacted by the registry.' : 'No details published.');
    for (const l of lines) {
      const p = document.createElement('p');
      if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(l)) { const a = document.createElement('a'); a.href = 'mailto:' + l; a.textContent = l; p.append(a); }
      else p.textContent = l.replace(/^tel:/, '');
      card.append(p);
    }
    frag.append(card);
  }
  return frag;
}

// ---------- page ----------
function status(msg, bad, link) {
  const s = $('#status'); s.textContent = msg; s.className = bad ? 'bad' : '';
  if (link) { const a = document.createElement('a'); a.href = link.href; a.rel = 'noreferrer'; a.textContent = link.text; s.append(a); }
}
let seq = 0;
async function run(raw) {
  const my = ++seq; $('#result').hidden = true;
  let t;
  try { t = classify(raw); } catch (e) { status(e.message, true); return; }
  if (!t) { status(''); return; }
  history.replaceState(null, '', '#q=' + encodeURIComponent(raw.trim()));
  status('Asking the registry...');
  try {
    const res = await lookup(t); if (my !== seq) return;
    const { rows, ents } = summarise(res);
    $('#result-title').textContent = res.t.kind === 'domain' ? (res.json.ldhName || res.name).toLowerCase() : res.name;
    $('#result-kind').textContent = { domain: 'Domain', ipv4: 'IPv4 address', ipv6: 'IPv6 address', asn: 'Autonomous system' }[t.kind];
    const dl = $('#summary'); dl.textContent = '';
    for (const [k, v] of rows) { const dt = document.createElement('dt'); dt.textContent = k; const dd = document.createElement('dd'); dd.textContent = v; dl.append(dt, dd); }
    const c = $('#contacts'); c.textContent = ''; const cards = contactCards(ents);
    if (cards.childNodes.length) { const h = document.createElement('h3'); h.className = 'sub'; h.textContent = 'Contacts'; c.append(h); const g = document.createElement('div'); g.className = 'cards'; g.append(cards); c.append(g); }
    $('#source').href = res.url; $('#source').rel = 'noreferrer'; $('#source').textContent = new URL(res.url).host;
    $('#raw').textContent = JSON.stringify(res.json, null, 2);
    $('#result').hidden = false; status('');
  } catch (e) { if (my === seq) status(e.message || 'Something went wrong.', true, e.link); }
}

$('#form').addEventListener('submit', (e) => { e.preventDefault(); run($('#q').value); });
// A link such as #q=example.com fills the box; nothing is sent until the visitor presses Look up.
function fromHash() {
  const q = new URLSearchParams(location.hash.slice(1)).get('q');
  if (q) { $('#q').value = q; $('#result').hidden = true; status('Press Look up to ask the registry about ' + q + '.'); $('#q').focus(); }
}
window.addEventListener('hashchange', fromHash); fromHash();
