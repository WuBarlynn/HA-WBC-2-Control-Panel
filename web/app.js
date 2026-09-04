/* HA-WBC-2 开机卡控制台前端逻辑 */
"use strict";

// ---------- 全局状态 ----------
const S = {
  token: localStorage.getItem("wbc_token") || "",
  overview: [],
  currentId: null,      // 当前抽屉中的设备
  pollTimer: null,
  progressTimer: null,  // 固件升级进度轮询
  authMode: "login",    // login | setup
  cardHTML: new Map(),  // 设备卡片渲染快照,用于差量更新
  drawerSnap: { b: "", k: "" }, // 抽屉动态区快照
  passkeys: 0,          // 当前访问主机名下可用的通行密钥数
  rpId: "",
  homeKitTimer: null,
  homeKitSnap: "",
};

const $ = (sel, root) => (root || document).querySelector(sel);

// ---------- 工具 ----------
function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function formatBytes(n) {
  if (typeof n !== "number" || !isFinite(n)) return "-";
  if (n >= 1 << 20) return (n / (1 << 20)).toFixed(n % (1 << 20) ? 1 : 0) + " MB";
  if (n >= 1 << 10) return (n / (1 << 10)).toFixed(0) + " KB";
  return n + " B";
}

function signalLevel(rssi) {
  if (rssi >= -55) return 4;
  if (rssi >= -65) return 3;
  if (rssi >= -75) return 2;
  return 1;
}

function fmtTime(s) {
  if (!s) return "";
  const d = new Date(s);
  if (isNaN(d) || d.getFullYear() < 2000) return "";
  return d.toLocaleString("zh-CN", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

// ---------- base64url 与 ArrayBuffer 互转(WebAuthn 用) ----------
const b64u = {
  enc(buf) {
    const bytes = new Uint8Array(buf);
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  },
  dec(s) {
    s = String(s).replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    const bin = atob(s);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
  },
};

// 浏览器是否具备使用通行密钥的条件
function passkeySupport() {
  if (!window.PublicKeyCredential || !navigator.credentials) return { ok: false, why: "当前浏览器不支持通行密钥" };
  if (!window.isSecureContext) return { ok: false, why: "通行密钥需要通过 HTTPS 或 localhost 访问" };
  if (/^\d+\.\d+\.\d+\.\d+$/.test(location.hostname) || location.hostname.includes(":")) {
    return { ok: false, why: "通行密钥无法在 IP 地址下使用,请通过 localhost 或域名访问" };
  }
  return { ok: true, why: "" };
}

function pkErrMsg(e) {
  if (e && e.name === "NotAllowedError") return "操作被取消或超时";
  if (e && e.name === "SecurityError") return "浏览器拒绝:请通过域名(或 localhost)+ HTTPS 访问";
  if (e && e.name === "InvalidStateError") return "此设备可能已注册过通行密钥";
  return (e && e.message) || String(e);
}

// ---------- API ----------
async function api(path, opts = {}) {
  const init = { method: opts.method || "GET", headers: {} };
  if (S.token) init.headers["Authorization"] = "Bearer " + S.token;
  if (opts.body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(opts.body);
  }
  let resp;
  try {
    resp = await fetch(path, init);
  } catch (e) {
    throw new Error("无法连接控制台服务");
  }
  let data = null;
  try { data = await resp.json(); } catch (e) { /* 非 JSON */ }
  if (resp.status === 401 && !opts.keepSession) {
    setToken("");
    showAuth("login");
    throw new Error((data && data.error) || "会话已过期,请重新登录");
  }
  if (!data || data.ok !== true) {
    throw new Error((data && data.error) || ("请求失败(HTTP " + resp.status + ")"));
  }
  return data.data;
}

function setToken(t) {
  S.token = t || "";
  if (t) localStorage.setItem("wbc_token", t);
  else localStorage.removeItem("wbc_token");
}

// ---------- 通知 ----------
function toast(msg, type) {
  type = type || "info";
  const iconId = type === "success" ? "i-check" : type === "error" ? "i-alert" : "i-info";
  const el = document.createElement("div");
  el.className = "toast " + type;
  el.innerHTML = `<svg class="icon"><use href="#${iconId}"/></svg><span>${esc(msg)}</span>`;
  $("#toasts").appendChild(el);
  setTimeout(() => {
    el.classList.add("out");
    setTimeout(() => el.remove(), 260);
  }, 3600);
}

// ---------- 模态 ----------
function openModal(html) {
  stopHomeKitStatusPoll();
  $("#modal").className = "modal";
  $("#modal").innerHTML = html;
  $("#modal-mask").classList.remove("hidden");
}
function closeModal() {
  stopHomeKitStatusPoll();
  $("#modal-mask").classList.add("hidden");
  $("#modal").className = "modal";
  $("#modal").innerHTML = "";
}
// 弹窗不响应遮罩点击,避免误触关闭,只能通过按钮关闭

// 危险操作二次确认
function confirmDialog({ title, text, confirmText = "确认", danger = true }) {
  return new Promise((resolve) => {
    openModal(`
      <h3>${esc(title)}</h3>
      <p class="modal-sub"></p>
      ${danger ? `<div class="modal-warning"><svg class="icon"><use href="#i-alert"/></svg><span>${esc(text)}</span></div>`
                : `<p class="modal-sub">${esc(text)}</p>`}
      <div class="modal-actions">
        <button class="btn btn-ghost" id="cfm-no">取消</button>
        <button class="btn ${danger ? "btn-danger" : "btn-primary"}" id="cfm-yes">${esc(confirmText)}</button>
      </div>`);
    $("#cfm-no").onclick = () => { closeModal(); resolve(false); };
    $("#cfm-yes").onclick = () => { closeModal(); resolve(true); };
  });
}

// 按钮加载态
async function withBusy(btn, fn) {
  if (!btn || btn.disabled) return;
  const old = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = `<svg class="icon spin"><use href="#i-restart"/></svg><span>请稍候</span>`;
  try {
    return await fn();
  } finally {
    btn.disabled = false;
    btn.innerHTML = old;
  }
}

// ---------- 主题 ----------
function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  localStorage.setItem("wbc_theme", theme);
  const use = $("#btn-theme use");
  if (use) use.setAttribute("href", theme === "dark" ? "#i-moon" : "#i-sun");
}
function initTheme() {
  const saved = localStorage.getItem("wbc_theme");
  const prefer = window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  applyTheme(saved || prefer);
}
$("#btn-theme").addEventListener("click", () => {
  applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
});

// ---------- 视图切换 ----------
function showAuth(mode) {
  S.authMode = mode;
  stopPolling();
  $("#view-app").classList.add("hidden");
  $("#view-auth").classList.remove("hidden");
  closeDrawer();
  closeModal();
  const isSetup = mode === "setup";
  $("#auth-title").textContent = isSetup ? "初始化系统" : "登录";
  $("#auth-sub").textContent = isSetup ? "首次使用,请设置管理员密码(至少 6 位)" : "请输入管理员密码";
  $("#auth-confirm-wrap").classList.toggle("hidden", !isSetup);
  $("#auth-confirm").required = isSetup;
  $("#auth-submit").textContent = isSetup ? "完成初始化" : "登 录";
  $("#auth-password").value = "";
  $("#auth-confirm").value = "";
  setupPasskeyUI();
  setTimeout(() => $("#auth-password").focus(), 50);
}

// 根据可用性决定登录页通行密钥按钮的展示
function setupPasskeyUI() {
  const btn = $("#btn-passkey-login");
  const divider = $("#pk-divider");
  const hint = $("#pk-unavailable");
  btn.classList.add("hidden");
  divider.classList.add("hidden");
  hint.classList.add("hidden");
  if (S.authMode !== "login" || S.passkeys <= 0) return;
  const sup = passkeySupport();
  if (sup.ok) {
    btn.classList.remove("hidden");
    divider.classList.remove("hidden");
  } else {
    hint.textContent = "已注册通行密钥,但" + sup.why;
    hint.classList.remove("hidden");
  }
}

// 通行密钥登录
$("#btn-passkey-login").addEventListener("click", async (e) => {
  await withBusy(e.currentTarget, async () => {
    try {
      const opts = await api("/api/passkey/login/begin", { method: "POST", keepSession: true });
      const pk = opts.publicKey;
      pk.challenge = b64u.dec(pk.challenge);
      pk.allowCredentials = (pk.allowCredentials || []).map((c) => ({ ...c, id: b64u.dec(c.id) }));
      const cred = await navigator.credentials.get({ publicKey: pk });
      const data = await api("/api/passkey/login/finish", {
        method: "POST",
        keepSession: true,
        body: {
          id: cred.id,
          clientDataJSON: b64u.enc(cred.response.clientDataJSON),
          authenticatorData: b64u.enc(cred.response.authenticatorData),
          signature: b64u.enc(cred.response.signature),
        },
      });
      setToken(data.token);
      toast("通行密钥登录成功", "success");
      showApp();
    } catch (err) {
      toast(pkErrMsg(err), "error");
    }
  });
});

// 注册通行密钥(在系统设置中调用)
async function registerPasskey(name) {
  const opts = await api("/api/passkey/register/begin", { method: "POST" });
  const pk = opts.publicKey;
  pk.challenge = b64u.dec(pk.challenge);
  pk.user.id = b64u.dec(pk.user.id);
  pk.excludeCredentials = (pk.excludeCredentials || []).map((c) => ({ ...c, id: b64u.dec(c.id) }));
  const cred = await navigator.credentials.create({ publicKey: pk });
  await api("/api/passkey/register/finish", {
    method: "POST",
    body: {
      name,
      clientDataJSON: b64u.enc(cred.response.clientDataJSON),
      attestationObject: b64u.enc(cred.response.attestationObject),
    },
  });
  S.passkeys++;
}

function showApp() {
  $("#view-auth").classList.add("hidden");
  $("#view-app").classList.remove("hidden");
  refreshOverview(true);
  startPolling();
}

// ---------- 认证 ----------
$("#auth-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const pwd = $("#auth-password").value;
  if (S.authMode === "setup") {
    if (pwd !== $("#auth-confirm").value) {
      toast("两次输入的密码不一致", "error");
      return;
    }
  }
  await withBusy($("#auth-submit"), async () => {
    try {
      const path = S.authMode === "setup" ? "/api/setup" : "/api/login";
      const data = await api(path, { method: "POST", body: { password: pwd }, keepSession: true });
      setToken(data.token);
      toast(S.authMode === "setup" ? "初始化完成,欢迎使用" : "登录成功", "success");
      showApp();
    } catch (err) {
      toast(err.message, "error");
    }
  });
});

$("#btn-logout").addEventListener("click", async () => {
  try { await api("/api/logout", { method: "POST", keepSession: true }); } catch (e) { /* 忽略 */ }
  setToken("");
  showAuth("login");
});

// ---------- 系统设置(密码 + 通行密钥 + Apple 家庭) ----------
$("#btn-settings").addEventListener("click", openSystemSettings);

function openSystemSettings() {
  const sup = passkeySupport();
  openModal(`
    <h3>系统设置</h3>
    <div class="settings-sub"><svg class="icon"><use href="#i-home"/></svg>Apple 家庭</div>
    <div id="hk-panel"><div class="skeleton" style="height:164px"></div></div>
    <div class="settings-sub"><svg class="icon"><use href="#i-shield"/></svg>修改管理员密码</div>
    <form id="pwd-form">
      <div class="field"><label>原密码</label><input type="password" id="pwd-old" required></div>
      <div class="field"><label>新密码</label><input type="password" id="pwd-new" required minlength="6" placeholder="至少 6 位"></div>
      <div class="field"><label>确认新密码</label><input type="password" id="pwd-new2" required></div>
      <button type="submit" class="btn btn-primary btn-block" id="pwd-save">保存新密码</button>
    </form>
    <div class="settings-sub"><svg class="icon"><use href="#i-key"/></svg>通行密钥</div>
    <div class="pk-list" id="pk-list"><p class="muted" style="font-size:12.5px">加载中...</p></div>
    ${sup.ok ? `
    <form id="pk-add-form">
      <div class="field">
        <input id="pk-name" maxlength="30" placeholder="名称,如:MacBook 指纹(可留空)">
      </div>
      <button type="submit" class="btn btn-block" id="pk-add-btn"><svg class="icon"><use href="#i-plus"/></svg>添加通行密钥</button>
    </form>
    <p class="pk-hint" style="text-align:left">通行密钥与当前访问的域名绑定,换用其他地址访问时需另行注册</p>
    ` : `<p class="pk-hint" style="text-align:left">无法在此添加通行密钥:${esc(sup.why)}</p>`}
    <div class="modal-actions">
      <button type="button" class="btn btn-ghost" id="settings-close">关闭</button>
    </div>`);
  $("#modal").classList.add("modal-settings");
  $("#settings-close").onclick = closeModal;

  $("#pwd-form").onsubmit = async (e) => {
    e.preventDefault();
    if ($("#pwd-new").value !== $("#pwd-new2").value) {
      toast("两次输入的新密码不一致", "error");
      return;
    }
    await withBusy($("#pwd-save"), async () => {
      try {
        await api("/api/password", { method: "POST", body: { old: $("#pwd-old").value, new: $("#pwd-new").value } });
        toast("密码已修改", "success");
        $("#pwd-old").value = $("#pwd-new").value = $("#pwd-new2").value = "";
      } catch (err) {
        toast(err.message, "error");
      }
    });
  };

  const addForm = $("#pk-add-form");
  if (addForm) {
    addForm.onsubmit = async (e) => {
      e.preventDefault();
      await withBusy($("#pk-add-btn"), async () => {
        try {
          await registerPasskey($("#pk-name").value.trim());
          toast("通行密钥添加成功", "success");
          $("#pk-name").value = "";
          loadPasskeyList();
        } catch (err) {
          toast(pkErrMsg(err), "error");
        }
      });
    };
  }

  S.homeKitSnap = "";
  loadHomeKitPanel(true);
  loadPasskeyList();
}

function stopHomeKitStatusPoll() {
  if (S.homeKitTimer) {
    clearInterval(S.homeKitTimer);
    S.homeKitTimer = null;
  }
}

async function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const input = document.createElement("textarea");
  input.value = text;
  input.style.position = "fixed";
  input.style.opacity = "0";
  document.body.appendChild(input);
  input.select();
  document.execCommand("copy");
  input.remove();
}

async function loadHomeKitPanel(forceRender) {
  const box = $("#hk-panel");
  if (!box) return;
  let h;
  try {
    h = await api("/api/homekit");
  } catch (err) {
    box.innerHTML = `<div class="card-err">${esc(err.message)}</div>`;
    return;
  }
  const snap = JSON.stringify(h);
  if (!forceRender && snap === S.homeKitSnap) return;
  S.homeKitSnap = snap;
  renderHomeKitPanel(box, h);

  stopHomeKitStatusPoll();
  if (h.enabled && h.running && !h.paired) {
    S.homeKitTimer = setInterval(() => loadHomeKitPanel(false), 2500);
  }
}

function renderHomeKitPanel(box, h) {
  const state = !h.enabled
    ? { cls: "", text: "已停用", sub: h.paired ? "已保留现有配对,重新启用后自动恢复" : "启用后可用家庭 App、Siri 与自动化控制" }
    : h.error
      ? { cls: "err", text: "运行异常", sub: h.error }
      : h.running && h.paired
        ? { cls: "ok", text: "已配对", sub: `已授权 ${h.pairingCount || 1} 个 Apple 家庭控制器` }
        : h.running
          ? { cls: "warn", text: "等待配对", sub: "桥已在局域网广播,可从家庭 App 添加" }
          : { cls: "warn", text: "正在启动", sub: "正在准备 HomeKit 桥" };
  const pairing = h.enabled && h.running && !h.paired ? `
    <div class="hk-pairing">
      <div class="hk-qr-wrap">
        ${h.qrCode ? `<img class="hk-qr" src="${h.qrCode}" alt="Apple 家庭配对二维码">` : `<div class="hk-qr-missing">二维码生成失败</div>`}
      </div>
      <div class="hk-pair-copy">
        <span class="hk-eyebrow">HOMEKIT SETUP CODE</span>
        <strong class="hk-code">${esc(h.pin)}</strong>
        <button type="button" class="btn btn-sm" id="hk-copy"><svg class="icon"><use href="#i-copy"/></svg>复制配对码</button>
      </div>
    </div>
    <ol class="hk-steps">
      <li>打开 iPhone 或 iPad 的「家庭」App</li>
      <li>点右上角「+」→「添加配件」；扫码，或在「更多选项」中选择此桥</li>
      <li>确认添加 ${h.deviceCount} 台开机卡；配对状态会在这里自动更新</li>
    </ol>` : "";
  const paired = h.enabled && h.running && h.paired ? `
    <div class="hk-paired-note">
      <svg class="icon"><use href="#i-check"/></svg>
      <div><b>Apple 家庭已接管设备</b><span>每台开机卡包含电源、来电自启、童锁和温度组件</span></div>
    </div>` : "";

  box.innerHTML = `
    <div class="hk-card">
      <div class="hk-status-row">
        <div class="hk-mark"><svg class="icon"><use href="#i-home"/></svg></div>
        <div class="hk-status-copy"><b>${esc(h.name)}</b><span>${esc(state.sub)}</span></div>
        <span class="badge ${state.cls}">${esc(state.text)}</span>
      </div>
      ${pairing}
      ${paired}
      <form id="hk-form" class="hk-form">
        <div class="hk-field-grid">
          <div class="field"><label>桥名称</label><input id="hk-name" required maxlength="64" value="${esc(h.name)}"></div>
          <div class="field"><label>监听端口</label><input id="hk-port" required type="number" min="1" max="65535" value="${esc(h.port)}"></div>
        </div>
        <div class="field"><label>配对 PIN</label><input id="hk-pin" required inputmode="numeric" maxlength="10" value="${esc(h.pin)}" ${h.paired ? "readonly" : ""}><div class="hint">8 位数字；桥已配对时需先重置配对才能修改</div></div>
        <div class="toggle-row hk-enable-row">
          <div class="t-label"><div><div class="t-title">启用 Apple 家庭桥</div><div class="t-sub">占用 TCP ${esc(h.port)} 与局域网 UDP 5353 (mDNS)</div></div></div>
          <label class="switch"><input type="checkbox" id="hk-enabled" ${h.enabled ? "checked" : ""}><span class="slider"></span></label>
        </div>
        <button type="submit" class="btn btn-primary btn-block" id="hk-save">${h.enabled ? "保存并重启桥" : "启用并准备配对"}</button>
      </form>
      ${h.paired ? `<button type="button" class="btn btn-outline-danger btn-block hk-reset" id="hk-reset">重置 Apple 家庭配对</button>` : ""}
    </div>`;

  $("#hk-form").onsubmit = async (e) => {
    e.preventDefault();
    stopHomeKitStatusPoll();
    const submitted = {
      enabled: $("#hk-enabled").checked,
      name: $("#hk-name").value.trim(),
      pin: $("#hk-pin").value.trim(),
      port: Number($("#hk-port").value),
    };
    await withBusy($("#hk-save"), async () => {
      try {
        await api("/api/homekit", { method: "PUT", body: submitted });
        toast(submitted.enabled ? "Apple 家庭桥已启动" : "Apple 家庭桥已停用", "success");
        S.homeKitSnap = "";
        await loadHomeKitPanel(true);
      } catch (err) {
        toast(err.message, "error");
        await loadHomeKitPanel(true);
      }
    });
  };

  const copyBtn = $("#hk-copy");
  if (copyBtn) {
    copyBtn.onclick = async () => {
      try {
        await copyText(h.pin);
        toast("HomeKit 配对码已复制", "success");
      } catch (err) {
        toast("无法复制配对码", "error");
      }
    };
  }

  const resetBtn = $("#hk-reset");
  if (resetBtn) {
    resetBtn.onclick = async () => {
      const yes = await confirmDialog({
        title: "重置 Apple 家庭配对",
        text: "控制台会撤销现有家庭授权。请同时在 Apple 家庭 App 中移除此桥，之后才能重新添加。",
        confirmText: "重置配对",
      });
      if (!yes) { openSystemSettings(); return; }
      try {
        await api("/api/homekit/reset", { method: "POST" });
        toast("Apple 家庭配对已重置", "success");
      } catch (err) {
        toast(err.message, "error");
      }
      openSystemSettings();
    };
  }
}

// 加载并渲染通行密钥列表(系统设置弹窗内)
async function loadPasskeyList() {
  const box = $("#pk-list");
  if (!box) return;
  let list;
  try {
    list = await api("/api/passkey/list");
  } catch (err) {
    box.innerHTML = `<p class="muted" style="font-size:12.5px">${esc(err.message)}</p>`;
    return;
  }
  if (!list.length) {
    box.innerHTML = `<p class="muted" style="font-size:12.5px">尚未注册通行密钥,注册后可用指纹/面容一键登录</p>`;
    return;
  }
  box.innerHTML = list.map((p) => {
    const used = fmtTime(p.lastUsedAt);
    return `
    <div class="pk-item">
      <svg class="icon"><use href="#i-key"/></svg>
      <div class="pk-meta">
        <div class="pk-name">${esc(p.name)}</div>
        <div class="pk-sub">${esc(p.rpId)} · 注册于 ${fmtTime(p.createdAt)}${used ? " · 最近使用 " + used : ""}</div>
      </div>
      <button class="btn-icon" data-pk-del="${esc(p.id)}" title="删除"><svg class="icon"><use href="#i-trash"/></svg></button>
    </div>`;
  }).join("");
  box.querySelectorAll("[data-pk-del]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.dataset.pkDel;
      // confirmDialog 复用同一模态容器,结束后重新打开设置弹窗
      const yes = await confirmDialog({ title: "删除通行密钥", text: "删除后将无法再用它登录本控制台(设备系统里的通行密钥记录需自行清理)。", confirmText: "删除" });
      if (yes) {
        try {
          await api("/api/passkey/" + encodeURIComponent(id), { method: "DELETE" });
          toast("通行密钥已删除", "success");
          try {
            const st = await api("/api/state", { keepSession: true });
            S.passkeys = st.passkeys || 0;
          } catch (e) { /* 忽略 */ }
        } catch (err) {
          toast(err.message, "error");
        }
      }
      $("#btn-settings").click();
    });
  });
}

// ---------- 总览轮询 ----------
function startPolling() {
  stopPolling();
  S.pollTimer = setInterval(() => refreshOverview(false), 5000);
}
function stopPolling() {
  if (S.pollTimer) { clearInterval(S.pollTimer); S.pollTimer = null; }
}

async function refreshOverview(showLoading) {
  if (showLoading) {
    $("#device-grid").innerHTML = `
      <div class="skeleton" style="height:220px"></div>
      <div class="skeleton" style="height:220px"></div>
      <div class="skeleton" style="height:220px"></div>`;
  }
  try {
    S.overview = await api("/api/overview");
  } catch (err) {
    if (showLoading) $("#device-grid").innerHTML = "";
    toast(err.message, "error");
    return;
  }
  renderGrid();
  if (S.currentId) {
    const item = S.overview.find((x) => x.device.id === S.currentId);
    if (item) updateDrawerLive(item);
  }
}

$("#btn-refresh").addEventListener("click", (e) => withBusy(e.currentTarget, () => refreshOverview(false)));

// ---------- 仪表盘渲染 ----------
function cardInnerHTML(item) {
  const d = item.device;
  const info = item.info || {};
  const state = item.deviceState || {};
  const powerOn = state.pW === true;
  const powerBadge = !item.online
    ? `<span class="badge">离线</span>`
    : item.deviceState
      ? (powerOn
          ? `<span class="badge ok"><svg class="icon"><use href="#i-monitor"/></svg>主机已开机</span>`
          : `<span class="badge"><svg class="icon"><use href="#i-monitor"/></svg>主机已关机</span>`)
      : `<span class="badge warn">状态获取失败</span>`;
  return `
      <div class="card-head">
        <span class="dev-avatar"><svg class="icon"><use href="#i-chip"/></svg></span>
        <div class="card-title">
          <b>${esc(d.name)}</b>
          <span>${esc(d.addr)}</span>
        </div>
        <span class="dot ${item.online ? "on" : "off"}" title="${item.online ? "在线" : "离线"}"></span>
      </div>
      <div class="card-body">
        <div class="card-rows">
          <div class="card-row"><span class="k"><svg class="icon"><use href="#i-monitor"/></svg>电源状态</span><span class="v">${powerBadge}</span></div>
          <div class="card-row"><span class="k"><svg class="icon"><use href="#i-thermometer"/></svg>设备温度</span><span class="v">${typeof state.tP === "number" ? esc(state.tP) + " °C" : "-"}</span></div>
          <div class="card-row"><span class="k"><svg class="icon"><use href="#i-bolt"/></svg>来电自启</span><span class="v">${state.aS === true ? "已开启" : state.aS === false ? "已关闭" : "-"}</span></div>
          <div class="card-row"><span class="k"><svg class="icon"><use href="#i-shield"/></svg>童锁</span><span class="v">${state.cL === true ? "已开启" : state.cL === false ? "已关闭" : "-"}</span></div>
          <div class="card-row"><span class="k"><svg class="icon"><use href="#i-wifi"/></svg>WiFi</span><span class="v">${esc(info.wN || "-")}</span></div>
          <div class="card-row"><span class="k"><svg class="icon"><use href="#i-download"/></svg>固件版本</span><span class="v">${esc((item.status && item.status.fV) || info.fV || "-")}</span></div>
        </div>
        ${item.error ? `<div class="card-err">${esc(item.error)}</div>` : ""}
      </div>
      <div class="card-foot">
        <button class="btn btn-sm btn-success" data-act="power-on" data-id="${d.id}" ${!item.online ? "disabled" : ""}><svg class="icon"><use href="#i-power"/></svg>开机</button>
        <button class="btn btn-sm" data-act="power-off" data-id="${d.id}" ${!item.online ? "disabled" : ""}><svg class="icon"><use href="#i-power"/></svg>关机</button>
        <button class="btn btn-sm btn-ghost" data-act="open" data-id="${d.id}">详情</button>
      </div>`;
}

// 差量渲染:设备集合不变时只更新有数据变化的卡片,避免整页闪烁
function renderGrid() {
  const grid = $("#device-grid");
  const empty = $("#empty-state");
  const n = S.overview.length;
  const online = S.overview.filter((x) => x.online).length;
  $("#summary-line").textContent = n ? `共 ${n} 台设备 · ${online} 台在线 · ${n - online} 台离线` : "暂无设备";
  empty.classList.toggle("hidden", n > 0);
  grid.classList.toggle("hidden", n === 0);
  if (!n) { grid.innerHTML = ""; S.cardHTML.clear(); return; }

  const ids = S.overview.map((x) => x.device.id);
  const domIds = Array.from(grid.querySelectorAll(":scope > .card[data-id]")).map((c) => c.dataset.id);

  if (ids.join(",") !== domIds.join(",")) {
    // 设备增删或首次加载(骨架屏):整体重建
    S.cardHTML.clear();
    grid.innerHTML = S.overview.map((item) => {
      const inner = cardInnerHTML(item);
      S.cardHTML.set(item.device.id, inner);
      return `<div class="card" data-id="${item.device.id}">${inner}</div>`;
    }).join("");
    return;
  }

  for (const item of S.overview) {
    const id = item.device.id;
    const inner = cardInnerHTML(item);
    if (S.cardHTML.get(id) === inner) continue; // 数据无变化,不动 DOM
    const card = grid.querySelector(`:scope > .card[data-id="${id}"]`);
    if (card) card.innerHTML = inner;
    S.cardHTML.set(id, inner);
  }
}

// ---------- 设备详情抽屉 ----------
const INFO_FIELDS = [
  ["hN", "设备名称"],
  ["SN", "序列号"],
  ["mD", "型号"],
  ["mT", "设备类型"],
  ["wN", "WiFi 名称"],
  ["wI", "设备 IP", null, true],
  ["wM", "MAC 地址", null, true],
  ["mF", "闪存大小", (v) => formatBytes(v)],
  ["fV", "固件版本"],
  ["fU", "固件日期"],
  ["hV", "硬件版本"],
  ["hU", "硬件日期"],
];

function openDrawer(id) {
  S.currentId = id;
  const item = S.overview.find((x) => x.device.id === id);
  if (!item) return;
  renderDrawer(item);
  $("#drawer").classList.add("open");
  $("#drawer-mask").classList.remove("hidden");
  // 打开时拉取一次最新数据
  refreshOverview(false);
}

function closeDrawer() {
  S.currentId = null;
  stopProgressPoll();
  $("#drawer").classList.remove("open");
  $("#drawer-mask").classList.add("hidden");
}
$("#drawer-mask").addEventListener("click", closeDrawer);

function badgesHTML(item) {
  const info = item.info || {};
  const status = item.status || {};
  const state = item.deviceState || {};
  const out = [];
  out.push(item.online
    ? `<span class="badge ok"><svg class="icon"><use href="#i-check"/></svg>设备在线</span>`
    : `<span class="badge err">设备离线</span>`);
  if (item.online) {
    const oL = info.oL !== undefined ? info.oL : status.oL;
    out.push(oL ? `<span class="badge ok"><svg class="icon"><use href="#i-wifi"/></svg>已联网</span>`
                : `<span class="badge warn"><svg class="icon"><use href="#i-wifi"/></svg>未联网</span>`);
    if (status.pE === true) out.push(`<span class="badge err">WiFi 密码错误</span>`);
    if (status.wP === false) out.push(`<span class="badge warn">未配网</span>`);
    if (item.deviceState) {
      out.push(state.pW === true
        ? `<span class="badge ok"><svg class="icon"><use href="#i-monitor"/></svg>主机已开机</span>`
        : `<span class="badge"><svg class="icon"><use href="#i-monitor"/></svg>主机已关机</span>`);
      if (typeof state.tP === "number") {
        out.push(`<span class="badge"><svg class="icon"><use href="#i-thermometer"/></svg>${esc(state.tP)} °C</span>`);
      }
    }
  }
  return out.join("");
}

function kvHTML(item) {
  const info = item.info || {};
  if (!item.info) {
    return `<div class="card-err">${esc(item.error || "无法获取设备信息")}</div>`;
  }
  return `<div class="kv">` + INFO_FIELDS.map(([key, label, fmt, mono]) => {
    let v = info[key];
    v = fmt ? fmt(v) : (v === undefined || v === "" ? "-" : String(v));
    return `<div class="item"><div class="k">${label}</div><div class="v${mono ? " mono" : ""}" title="${esc(v)}">${esc(v)}</div></div>`;
  }).join("") + `</div>`;
}

function renderDrawer(item) {
  const d = item.device;
  S.drawerSnap = { b: badgesHTML(item), k: kvHTML(item) };
  $("#drawer-content").innerHTML = `
  <div class="drawer-head">
    <span class="dev-avatar"><svg class="icon"><use href="#i-chip"/></svg></span>
    <div class="card-title">
      <b>${esc(d.name)}</b>
      <span>${esc(d.addr)}</span>
    </div>
    <button class="btn-icon" data-act="drawer-refresh" title="刷新"><svg class="icon"><use href="#i-restart"/></svg></button>
    <button class="btn-icon" data-act="drawer-close" title="关闭"><svg class="icon"><use href="#i-x"/></svg></button>
  </div>
  <div class="drawer-body">

    <div id="d-badges" style="display:flex;gap:8px;flex-wrap:wrap">${badgesHTML(item)}</div>

    <div class="section">
      <div class="section-head"><h4><svg class="icon"><use href="#i-info"/></svg>设备信息</h4></div>
      <div id="d-kv">${kvHTML(item)}</div>
    </div>

    <div class="section">
      <div class="section-head"><h4><svg class="icon"><use href="#i-power"/></svg>电源控制</h4></div>
      <div class="ctrl-grid">
        <button class="btn btn-success" data-act="power-on" data-id="${d.id}"><svg class="icon"><use href="#i-power"/></svg>开机</button>
        <button class="btn" data-act="power-off" data-id="${d.id}"><svg class="icon"><use href="#i-power"/></svg>关机</button>
        <button class="btn" data-act="dev-restart" data-id="${d.id}"><svg class="icon"><use href="#i-restart"/></svg>重启开机卡</button>
        <button class="btn btn-warn" data-act="force-shutdown" data-id="${d.id}"><svg class="icon"><use href="#i-bolt"/></svg>强制关机</button>
      </div>
      <p class="note">强制关机相当于长按主机电源键,可能导致数据丢失</p>
    </div>

    <div class="section">
      <div class="section-head"><h4><svg class="icon"><use href="#i-gear"/></svg>开关设置</h4></div>
      <div class="toggle-row">
        <div class="t-label">
          <svg class="icon"><use href="#i-bolt"/></svg>
          <div><div class="t-title">来电自启动</div><div class="t-sub">通电后自动开机</div></div>
        </div>
        <label class="switch"><input type="checkbox" id="tg-autostart" ${item.deviceState && item.deviceState.aS ? "checked" : ""}><span class="slider"></span></label>
      </div>
      <div class="toggle-row">
        <div class="t-label">
          <svg class="icon"><use href="#i-shield"/></svg>
          <div><div class="t-title">童锁</div><div class="t-sub">锁定设备实体按键</div></div>
        </div>
        <label class="switch"><input type="checkbox" id="tg-childlock" ${item.deviceState && item.deviceState.cL ? "checked" : ""}><span class="slider"></span></label>
      </div>
      <p class="note">开关状态由设备实时返回</p>
    </div>

    <div class="section">
      <div class="section-head">
        <h4><svg class="icon"><use href="#i-wifi"/></svg>WiFi 设置</h4>
        <button class="btn btn-sm btn-ghost" data-act="wifi-scan" data-id="${d.id}">扫描附近 WiFi</button>
      </div>
      <div id="wifi-list-box"></div>
      <form id="wifi-form" autocomplete="off" style="margin-top:12px">
        <div class="field"><label>WiFi 名称 (SSID)</label><input id="wifi-ssid" required placeholder="选择上方扫描结果或手动输入"></div>
        <div class="field"><label>WiFi 密码</label><input id="wifi-pass" type="password" placeholder="留空表示开放网络"></div>
        <button type="submit" class="btn btn-primary btn-block" id="wifi-save">保存 WiFi 配置</button>
      </form>
      <p class="note">修改 WiFi 后设备将重新联网,若 IP 变化请在"编辑设备"中更新地址</p>
    </div>

    <div class="section">
      <div class="section-head">
        <h4><svg class="icon"><use href="#i-download"/></svg>固件更新</h4>
        <span class="muted" style="font-size:12px">当前版本 ${esc((item.info && item.info.fV) || "-")}</span>
      </div>
      <div class="ctrl-grid">
        <button class="btn" data-act="check-update" data-id="${d.id}">检查更新</button>
        <button class="btn btn-primary" data-act="firmware-update" data-id="${d.id}">执行更新</button>
      </div>
      <div class="progress-row hidden" id="fw-progress-row">
        <div class="progress"><i id="fw-progress-bar"></i></div>
        <span class="pct" id="fw-progress-pct">0%</span>
      </div>
    </div>

    <div class="section danger">
      <div class="section-head"><h4><svg class="icon"><use href="#i-alert"/></svg>设备管理</h4></div>
      <div class="ctrl-grid">
        <button class="btn" data-act="dev-edit" data-id="${d.id}"><svg class="icon"><use href="#i-edit"/></svg>编辑设备</button>
        <button class="btn" data-act="dev-test" data-id="${d.id}"><svg class="icon"><use href="#i-check"/></svg>测试连接</button>
        <button class="btn btn-outline-danger" data-act="factory-reset" data-id="${d.id}"><svg class="icon"><use href="#i-alert"/></svg>恢复出厂设置</button>
        <button class="btn btn-outline-danger" data-act="dev-delete" data-id="${d.id}"><svg class="icon"><use href="#i-trash"/></svg>删除设备</button>
      </div>
    </div>
  </div>`;

  // 开关事件
  $("#tg-autostart").addEventListener("change", (e) => setFlag(d.id, "autostart", e.target));
  $("#tg-childlock").addEventListener("change", (e) => setFlag(d.id, "childlock", e.target));

  // WiFi 表单
  $("#wifi-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const ssid = $("#wifi-ssid").value.trim();
    const ok = await confirmDialog({
      title: "修改设备 WiFi",
      text: `确定将设备 WiFi 切换到「${ssid}」吗?配置错误可能导致设备离线。`,
      confirmText: "确认修改",
    });
    if (!ok) return;
    await withBusy($("#wifi-save"), async () => {
      try {
        const res = await api(`/api/devices/${d.id}/wifi`, { method: "POST", body: { ssid, password: $("#wifi-pass").value } });
        toast((res && res.message) || "WiFi 配置已下发", "success");
      } catch (err) {
        toast(err.message, "error");
      }
    });
  });

  // 若固件正在升级,恢复进度轮询
  if (item.info && typeof item.info.fG === "number" && item.info.fG > 0 && item.info.fG < 100) {
    startProgressPoll(d.id);
  }
}

// 轮询时仅更新动态数据,且内容无变化时不动 DOM,避免闪烁和打断表单输入
function updateDrawerLive(item) {
  const badges = $("#d-badges");
  const kv = $("#d-kv");
  const bh = badgesHTML(item);
  const kh = kvHTML(item);
  if (badges && S.drawerSnap.b !== bh) { badges.innerHTML = bh; S.drawerSnap.b = bh; }
  if (kv && S.drawerSnap.k !== kh) { kv.innerHTML = kh; S.drawerSnap.k = kh; }
  const state = item.deviceState;
  const autoStart = $("#tg-autostart");
  const childLock = $("#tg-childlock");
  if (state && autoStart && !autoStart.disabled) autoStart.checked = state.aS === true;
  if (state && childLock && !childLock.disabled) childLock.checked = state.cL === true;
}

// ---------- 设备操作 ----------
async function setFlag(id, kind, inputEl) {
  const state = inputEl.checked;
  inputEl.disabled = true;
  try {
    await api(`/api/devices/${id}/${kind}`, { method: "POST", body: { state } });
    toast(`${kind === "autostart" ? "来电自启动" : "童锁"}已${state ? "开启" : "关闭"}`, "success");
  } catch (err) {
    inputEl.checked = !state; // 失败回滚
    toast(err.message, "error");
  } finally {
    inputEl.disabled = false;
  }
}

async function doPower(id, on, btn) {
  await withBusy(btn, async () => {
    try {
      const res = await api(`/api/devices/${id}/power`, { method: "POST", body: { state: on } });
      toast((res && res.message) || "指令已发送", "success");
      setTimeout(() => refreshOverview(false), 800);
    } catch (err) {
      toast(err.message, "error");
    }
  });
}

// 固件升级进度
function startProgressPoll(id) {
  stopProgressPoll();
  const row = $("#fw-progress-row");
  if (row) row.classList.remove("hidden");
  S.progressTimer = setInterval(async () => {
    try {
      const res = await api(`/api/devices/${id}/update-progress`);
      const p = parseInt(res.progress, 10) || 0;
      const bar = $("#fw-progress-bar"), pct = $("#fw-progress-pct");
      if (bar) bar.style.width = p + "%";
      if (pct) pct.textContent = p + "%";
      if (p >= 100) {
        stopProgressPoll();
        toast("固件更新完成", "success");
        refreshOverview(false);
      }
    } catch (err) {
      stopProgressPoll();
      toast("获取更新进度失败: " + err.message, "error");
    }
  }, 1000);
}
function stopProgressPoll() {
  if (S.progressTimer) { clearInterval(S.progressTimer); S.progressTimer = null; }
}

// ---------- 添加 / 编辑设备 ----------
function deviceModal(dev) {
  const isEdit = !!dev;
  openModal(`
    <h3>${isEdit ? "编辑设备" : "添加开机卡"}</h3>
    <p class="modal-sub">${isEdit ? "修改设备信息,保存后自动重新连接" : "填写局域网内 HA-WBC-2 开机卡的信息"}</p>
    <form id="dev-form">
      <div class="field">
        <label>设备名称</label>
        <input id="dev-name" required maxlength="30" placeholder="例如:客厅电脑" value="${isEdit ? esc(dev.name) : ""}">
      </div>
      <div class="field">
        <label>设备地址</label>
        <input id="dev-addr" required placeholder="例如:10.10.0.139" value="${isEdit ? esc(dev.addr) : ""}">
        <div class="hint">开机卡在局域网中的 IP 地址,可在其官方 App 或路由器中查看</div>
      </div>
      <div class="field">
        <label>WiFi 密码</label>
        <input id="dev-pass" type="password" ${isEdit ? "" : "required"} placeholder="${isEdit ? "留空表示不修改" : "开机卡所连 WiFi 的密码,用于登录设备"}">
        <div class="hint">设备使用所连 WiFi 的密码作为登录凭证</div>
      </div>
      <div class="modal-actions">
        <button type="button" class="btn btn-ghost" id="dev-cancel">取消</button>
        <button type="submit" class="btn btn-primary" id="dev-save">${isEdit ? "保存" : "添加并连接"}</button>
      </div>
    </form>`);
  $("#dev-cancel").onclick = closeModal;
  $("#dev-form").onsubmit = async (e) => {
    e.preventDefault();
    const body = {
      name: $("#dev-name").value.trim(),
      addr: $("#dev-addr").value.trim(),
      password: $("#dev-pass").value,
    };
    await withBusy($("#dev-save"), async () => {
      try {
        let saved;
        if (isEdit) {
          saved = await api(`/api/devices/${dev.id}`, { method: "PUT", body });
        } else {
          saved = await api("/api/devices", { method: "POST", body });
        }
        closeModal();
        toast(isEdit ? "设备已更新" : "设备已添加", "success");
        // 自动测试连通性
        try {
          await api(`/api/devices/${saved.id}/test`, { method: "POST" });
          toast("设备连接成功", "success");
        } catch (err) {
          toast("设备已保存,但连接失败: " + err.message, "error");
        }
        await refreshOverview(false);
      } catch (err) {
        toast(err.message, "error");
      }
    });
  };
  setTimeout(() => $("#dev-name").focus(), 60);
}

$("#btn-add").addEventListener("click", () => deviceModal(null));
$("#btn-add-empty").addEventListener("click", () => deviceModal(null));

// ---------- 全局动作分发 ----------
document.addEventListener("click", async (e) => {
  const el = e.target.closest("[data-act]");
  if (!el) return;
  const act = el.dataset.act;
  const id = el.dataset.id;
  const item = id ? S.overview.find((x) => x.device.id === id) : null;
  const dev = item ? item.device : null;

  switch (act) {
    case "open":
      openDrawer(id);
      break;
    case "drawer-close":
      closeDrawer();
      break;
    case "drawer-refresh":
      await withBusy(el, () => refreshOverview(false));
      toast("已刷新", "success");
      break;

    case "power-on":
      doPower(id, true, el);
      break;
    case "power-off": {
      const ok = await confirmDialog({ title: "关机确认", text: `确定要关闭「${dev ? dev.name : ""}」的主机吗?`, confirmText: "关机" });
      if (ok) doPower(id, false, el);
      break;
    }
    case "dev-restart": {
      const ok = await confirmDialog({ title: "重启开机卡", text: "重启期间设备将短暂离线,确定继续吗?", confirmText: "重启", danger: false });
      if (!ok) break;
      await withBusy(el, async () => {
        try {
          const res = await api(`/api/devices/${id}/restart`, { method: "POST" });
          toast((res && res.message) || "重启指令已发送", "success");
        } catch (err) { toast(err.message, "error"); }
      });
      break;
    }
    case "force-shutdown": {
      const ok = await confirmDialog({ title: "强制关机", text: "相当于长按电源键,未保存的数据将丢失!确定强制关机吗?", confirmText: "强制关机" });
      if (!ok) break;
      await withBusy(el, async () => {
        try {
          const res = await api(`/api/devices/${id}/force-shutdown`, { method: "POST" });
          toast((res && res.message) || "已发送强制关机指令", "success");
          setTimeout(() => refreshOverview(false), 800);
        } catch (err) { toast(err.message, "error"); }
      });
      break;
    }

    case "wifi-scan": {
      const box = $("#wifi-list-box");
      box.innerHTML = `<div class="skeleton" style="height:120px;margin-top:10px"></div>`;
      await withBusy(el, async () => {
        try {
          const res = await api(`/api/devices/${id}/wifi-list`);
          const list = (res && res.list) || [];
          if (!list.length) {
            box.innerHTML = `<p class="note">未扫描到 WiFi</p>`;
            return;
          }
          list.sort((a, b) => (b.r || -99) - (a.r || -99));
          box.innerHTML = `<div class="wifi-list">` + list.map((w) => `
            <div class="wifi-item" data-ssid="${esc(w.s)}">
              <div class="w-name"><svg class="icon"><use href="#i-wifi"/></svg><span>${esc(w.s)}</span></div>
              <div class="w-meta">
                <span>${w.r} dBm</span>
                <span class="bars" data-level="${signalLevel(w.r)}"><i></i><i></i><i></i><i></i></span>
              </div>
            </div>`).join("") + `</div>`;
          box.querySelectorAll(".wifi-item").forEach((n) => {
            n.addEventListener("click", () => {
              box.querySelectorAll(".wifi-item").forEach((m) => m.classList.remove("selected"));
              n.classList.add("selected");
              $("#wifi-ssid").value = n.dataset.ssid;
              $("#wifi-pass").focus();
            });
          });
        } catch (err) {
          box.innerHTML = "";
          toast(err.message, "error");
        }
      });
      break;
    }

    case "check-update":
      await withBusy(el, async () => {
        try {
          const res = await api(`/api/devices/${id}/check-update?fs_version=1.0.3`);
          toast(res && res.latest ? (res.message || "已经是最新版本") : "已完成更新检查", "success");
        } catch (err) { toast(err.message, "error"); }
      });
      break;
    case "firmware-update": {
      const ok = await confirmDialog({ title: "固件更新", text: "更新期间请勿断开设备电源。确定开始更新固件吗?", confirmText: "开始更新", danger: false });
      if (!ok) break;
      await withBusy(el, async () => {
        try {
          await api(`/api/devices/${id}/firmware-update`, { method: "POST" });
          toast("固件更新已开始", "success");
          startProgressPoll(id);
        } catch (err) { toast(err.message, "error"); }
      });
      break;
    }

    case "dev-test":
      await withBusy(el, async () => {
        try {
          await api(`/api/devices/${id}/test`, { method: "POST" });
          toast("设备连接正常,登录成功", "success");
          refreshOverview(false);
        } catch (err) { toast(err.message, "error"); }
      });
      break;
    case "dev-edit":
      if (dev) deviceModal(dev);
      break;
    case "factory-reset": {
      const ok = await confirmDialog({ title: "恢复出厂设置", text: `设备「${dev ? dev.name : ""}」的所有配置(包括配网信息)将被清除!确定继续吗?`, confirmText: "恢复出厂" });
      if (!ok) break;
      await withBusy(el, async () => {
        try {
          const res = await api(`/api/devices/${id}/factory-reset`, { method: "POST" });
          toast((res && res.message) || "已恢复出厂设置", "success");
          refreshOverview(false);
        } catch (err) { toast(err.message, "error"); }
      });
      break;
    }
    case "dev-delete": {
      const ok = await confirmDialog({ title: "删除设备", text: `确定从控制台删除「${dev ? dev.name : ""}」吗?仅移除记录,不影响设备本身。`, confirmText: "删除" });
      if (!ok) break;
      try {
        await api(`/api/devices/${id}`, { method: "DELETE" });
        toast("设备已删除", "success");
        closeDrawer();
        refreshOverview(false);
      } catch (err) { toast(err.message, "error"); }
      break;
    }
  }
});

// ---------- 启动 ----------
async function boot() {
  initTheme();
  try {
    const st = await api("/api/state", { keepSession: true });
    S.passkeys = st.passkeys || 0;
    S.rpId = st.rpId || "";
    if (!st.initialized) showAuth("setup");
    else if (st.authed) showApp();
    else showAuth("login");
  } catch (err) {
    toast(err.message, "error");
    showAuth("login");
  }
}
boot();
