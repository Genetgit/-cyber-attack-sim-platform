const $ = (s, r = document) => r.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmt = ts => ts ? new Date(ts).toLocaleString() : "-";
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function api(path, opts = {}) {
  let res;
  try {
    res = await fetch(CONFIG.API_BASE_URL + path, {
      ...opts, headers: { "X-API-Key": CONFIG.API_KEY, "Content-Type": "application/json" }
    });
  } catch { throw new Error("Cannot reach the backend. Check API_BASE_URL in config.js and that the server is running."); }
  let data = null;
  try { data = await res.json(); } catch {}
  if (!res.ok) throw new Error((data && data.error) || `Request failed (HTTP ${res.status})`);
  return data;
}

function setStatus(ok, msg) {
  const c = $("#conn"), e = $("#err");
  c.textContent = ok ? "Live" : "Offline";
  c.className = "pill " + (ok ? "live" : "off");
  e.hidden = ok; e.textContent = ok ? "" : msg;
}

function poll(fn, ms) {
  (async () => {
    for (;;) {
      try { await fn(); setStatus(true); } catch (e) { setStatus(false, e.message); }
      await sleep(ms);
    }
  })();
}

const sevBadge = s => `<span class="badge ${esc(s)}">${esc(s)}</span>`;
const statusBadge = s => `<span class="badge ${esc(s)}">${esc(String(s).replace("_", " "))}</span>`;
const meter = (score, sev) => `<div class="meter"><i class="${esc(sev)}" style="width:${+score * 0.6}px"></i><b>${+score}</b></div>`;
const eventRows = list => list.length ? list.map(e => `<tr><td class="mono">${fmt(e.timestamp)}</td><td>${esc(e.host_id)}</td>
  <td>${esc(e.event_type)}</td><td class="mono">${esc(e.src_ip)}</td><td>${esc(e.username)}</td><td class="raw mono">${esc(e.raw)}</td></tr>`).join("")
  : `<tr><td colspan="6" class="empty">No events yet.</td></tr>`;
const EVENT_HEAD = "<tr><th>Time</th><th>Host</th><th>Type</th><th>Source IP</th><th>User</th><th>Log line</th></tr>";
