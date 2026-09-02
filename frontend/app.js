const API = (window.location.origin.includes("127.0.0.1:8000") || window.location.origin.includes("localhost:8000"))
  ? "http://127.0.0.1:8000"
  : window.location.origin;
let currentAlertId=null;
let currentUser=null;

/* ── TOAST ── */
function toast(msg,type="info"){
  const el=document.getElementById("toast");
  el.textContent=msg;el.className=`toast show ${type}`;
  clearTimeout(el._t);el._t=setTimeout(()=>{el.className="toast";},3500);
}

/* ── CLOCK ── */
function updateClock(){
  const now=new Date();
  const el=document.getElementById("topbar-time");
  if(el)el.textContent=now.toUTCString().replace("GMT","UTC").slice(5,25);
}
setInterval(updateClock,1000);updateClock();

/* ── AUTH ── */
async function handleLogin(e){
  e.preventDefault();
  const un=document.getElementById("login-username").value.trim();
  const pw=document.getElementById("login-password").value.trim();
  const btn=document.getElementById("login-btn");
  const errEl=document.getElementById("login-error");
  errEl.textContent="";
  btn.disabled=true;document.getElementById("login-btn-text").textContent="Signing in…";
  try{
    const r=await fetch(`${API}/api/login`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:un,password:pw})});
    const d=await r.json();
    if(!r.ok||!d.success){errEl.textContent=d.detail||"Invalid credentials";btn.disabled=false;document.getElementById("login-btn-text").textContent="Sign In to Dashboard";return;}
    currentUser=d.user;
    localStorage.setItem("aegis_token",d.token);
    localStorage.setItem("aegis_user",JSON.stringify(d.user));
    applyUserUI();
    document.getElementById("page-login").style.display="none";
    document.getElementById("page-app").classList.remove("app-hidden");
    loadDashboard();
    startAutoRefresh();
    toast(`Welcome back, ${d.user.name}!`,"success");
  }catch{
    errEl.textContent="Cannot reach server. Is the backend running?";
    btn.disabled=false;document.getElementById("login-btn-text").textContent="Sign In to Dashboard";
  }
}

function handleLogout(){
  localStorage.removeItem("aegis_token");localStorage.removeItem("aegis_user");currentUser=null;
  document.getElementById("page-app").classList.add("app-hidden");
  document.getElementById("page-login").style.display="flex";
  document.getElementById("login-password").value="";
  document.getElementById("login-error").textContent="";
  toast("Signed out of AegisGuard AI.","info");
}

function togglePassword(){
  const f=document.getElementById("login-password");
  f.type=f.type==="password"?"text":"password";
}

function applyUserUI(){
  if(!currentUser)return;
  const n=currentUser.name;
  const initials=n.split(" ").map(x=>x[0]).join("").toUpperCase().slice(0,2);
  const av=document.getElementById("sidebar-avatar");
  const un=document.getElementById("sidebar-user-name");
  const ur=document.getElementById("sidebar-user-role");
  if(av)av.textContent=initials;
  if(un)un.textContent=n;
  if(ur)ur.textContent=currentUser.role;
}

function checkAuth(){
  const token=localStorage.getItem("aegis_token");
  const user=localStorage.getItem("aegis_user");
  if(token&&user){
    try{
      currentUser=JSON.parse(user);
      applyUserUI();
      document.getElementById("page-login").style.display="none";
      document.getElementById("page-app").classList.remove("app-hidden");
      loadDashboard();
      startAutoRefresh();
    }catch{
      document.getElementById("page-login").style.display="flex";
    }
  }else{
    document.getElementById("page-login").style.display="flex";
  }
}

/* ── BADGE HELPERS ── */
function sevBadge(s){const m={Critical:"sev-critical",High:"sev-high",Medium:"sev-medium",Low:"sev-low"};return`<span class="sev-badge ${m[s]||"sev-low"}">${s}</span>`;}
function statusBadge(s){const m={"New":"st-new","Triage in Progress":"st-triage","Automated Action Taken":"st-action","Resolved":"st-resolved"};const short={"New":"New","Triage in Progress":"Triage","Automated Action Taken":"Action Taken","Resolved":"Resolved"};return`<span class="status-badge ${m[s]||"st-new"}">${short[s]||s}</span>`;}
function riskColor(n){if(n>=75)return"var(--c-critical)";if(n>=55)return"var(--c-high)";if(n>=30)return"var(--c-medium)";return"var(--c-low)";}
function riskCell(n){const c=riskColor(n);return`<div class="risk-cell"><span class="risk-num" style="color:${c}">${n}</span><div class="risk-bar"><div class="risk-fill" style="width:${n}%;background:${c}"></div></div></div>`;}
function fmtTs(ts){return`<span class="cell-ts">${(ts||"").slice(0,19).replace("T"," ")} UTC</span>`;}
function sourcePill(s){return`<span class="source-pill">${s}</span>`;}

/* ── VIEW NAV ── */
function showView(name){
  document.querySelectorAll(".view").forEach(v=>v.classList.remove("active"));
  document.querySelectorAll(".nav-item").forEach(n=>n.classList.remove("active"));
  const v=document.getElementById(`view-${name}`);if(v)v.classList.add("active");
  const ni=document.getElementById(`nav-${name}`);if(ni)ni.classList.add("active");
  const titles={dashboard:"Dashboard",alerts:"Alert Feed",playbooks:"Playbooks",audit:"Audit Log",notifications:"Notifications"};
  const crumbs={dashboard:"Overview",alerts:"All Alerts",playbooks:"Workflows",audit:"Activity Log",notifications:"Channel Config"};
  const t=document.getElementById("topbar-title");const b=document.getElementById("topbar-breadcrumb");
  if(t)t.textContent=titles[name]||name;if(b)b.textContent=crumbs[name]||"";
  if(name==="dashboard")loadDashboard();
  else if(name==="alerts")loadAlerts();
  else if(name==="audit")loadAuditAll();
  else if(name==="notifications")loadNotificationView();
  return false;
}

/* ── STATS ── */
async function loadStats(){
  try{
    const d=await fetch(`${API}/api/stats`).then(r=>r.json());
    ["total","critical","high","new","resolved","actions"].forEach(k=>{
      const el=document.getElementById(`stat-${k}`);
      if(el)el.textContent=d[k==="actions"?"actions_taken":k]??0;
    });
    const badge=document.getElementById("nav-badge-new");
    if(badge){badge.textContent=d.new;badge.className=d.new>0?"nav-badge show":"nav-badge";}
  }catch{}
}

/* ── DASHBOARD ── */
async function loadDashboard(){
  await loadStats();
  try{
    const alerts=await fetch(`${API}/api/alerts?sort_by=created_at&sort_dir=desc`).then(r=>r.json());
    const tbody=document.getElementById("dashboard-tbody");
    if(!tbody)return;
    if(!alerts.length){tbody.innerHTML=`<tr><td colspan="7" class="empty-cell">No alerts yet</td></tr>`;return;}
    tbody.innerHTML=alerts.slice(0,10).map(a=>`
      <tr onclick="openDrawer('${a.id}')">
        <td class="cell-id">${a.id}</td><td>${fmtTs(a.timestamp)}</td>
        <td>${sourcePill(a.source)}</td><td class="wrap-cell">${a.alert_type}</td>
        <td>${sevBadge(a.severity)}</td><td>${riskCell(a.risk_score)}</td><td>${statusBadge(a.status)}</td>
      </tr>`).join("");
  }catch{toast("Cannot connect to backend.","error");}
}

/* ── ALERT FEED ── */
async function loadAlerts(){
  const sev=document.getElementById("filter-severity").value;
  const src=document.getElementById("filter-source").value;
  const st=document.getElementById("filter-status").value;
  const sb=document.getElementById("sort-by").value;
  const params=new URLSearchParams({severity:sev,source:src,status:st,sort_by:sb,sort_dir:"desc"});
  const tbody=document.getElementById("alerts-tbody");
  if(tbody)tbody.innerHTML=`<tr><td colspan="8" class="empty-cell">Loading…</td></tr>`;
  try{
    const alerts=await fetch(`${API}/api/alerts?${params}`).then(r=>r.json());
    if(!alerts.length){if(tbody)tbody.innerHTML=`<tr><td colspan="8" class="empty-cell">No alerts match current filters</td></tr>`;return;}
    if(tbody)tbody.innerHTML=alerts.map(a=>`
      <tr onclick="openDrawer('${a.id}')">
        <td class="cell-id">${a.id}</td><td>${fmtTs(a.timestamp)}</td>
        <td>${sourcePill(a.source)}</td><td class="wrap-cell">${a.alert_type}</td>
        <td>${sevBadge(a.severity)}</td><td>${riskCell(a.risk_score)}</td><td>${statusBadge(a.status)}</td>
        <td><button class="action-chip small" onclick="event.stopPropagation();openDrawer('${a.id}')">View →</button></td>
      </tr>`).join("");
    loadStats();
  }catch{if(tbody)tbody.innerHTML=`<tr><td colspan="8" class="empty-cell">Error loading alerts</td></tr>`;}
}

/* ── AUDIT LOG ── */
async function loadAuditAll(){
  const tbody=document.getElementById("audit-tbody");
  if(tbody)tbody.innerHTML=`<tr><td colspan="5" class="empty-cell">Loading…</td></tr>`;
  try{
    const alerts=await fetch(`${API}/api/alerts`).then(r=>r.json());
    const logs=[];
    for(const a of alerts){
      const d=await fetch(`${API}/api/alerts/${a.id}`).then(r=>r.json());
      (d.audit_logs||[]).forEach(l=>logs.push({...l,alertId:a.id}));
    }
    logs.sort((a,b)=>b.timestamp.localeCompare(a.timestamp));
    const cnt=document.getElementById("audit-count");if(cnt)cnt.textContent=`${logs.length} entries`;
    if(!logs.length){if(tbody)tbody.innerHTML=`<tr><td colspan="5" class="empty-cell">No audit entries yet</td></tr>`;return;}
    if(tbody)tbody.innerHTML=logs.map(l=>`
      <tr>
        <td class="cell-ts">${(l.timestamp||"").slice(0,19).replace("T"," ")} UTC</td>
        <td class="cell-id">${l.alertId||l.alert_id}</td>
        <td><strong>${l.action}</strong></td><td>${l.actor}</td>
        <td style="max-width:300px;white-space:normal;color:var(--text-dim)">${l.details||"—"}</td>
      </tr>`).join("");
  }catch{if(tbody)tbody.innerHTML=`<tr><td colspan="5" class="empty-cell">Error loading audit log</td></tr>`;}
}

/* ── DRAWER ── */
async function openDrawer(alertId){
  currentAlertId=alertId;
  document.getElementById("drawer-overlay").classList.add("open");
  document.getElementById("alert-drawer").classList.add("open");
  try{await fetch(`${API}/api/alerts/${alertId}/triage`,{method:"POST"});}catch{}
  await refreshDrawer();
}

async function refreshDrawer(){
  if(!currentAlertId)return;
  try{
    const a=await fetch(`${API}/api/alerts/${currentAlertId}`).then(r=>r.json());
    document.getElementById("drawer-alert-id").textContent=a.id;
    document.getElementById("drawer-alert-title").textContent=a.title;
    const score=a.risk_score;const c=riskColor(score);
    const sevEl=document.getElementById("drawer-severity");
    sevEl.className=`sev-badge sev-${(a.severity||"low").toLowerCase()}`;sevEl.textContent=a.severity;
    document.getElementById("drawer-risk-score").textContent=score;
    document.getElementById("drawer-risk-score").style.color=c;
    const bar=document.getElementById("drawer-risk-bar");bar.style.width=`${score}%`;bar.style.background=c;
    document.getElementById("drawer-ai-summary").textContent=a.ai_summary||"No summary available.";
    // IOCs
    const iocEl=document.getElementById("drawer-iocs");iocEl.innerHTML="";
    let iocs={};try{iocs=JSON.parse(a.iocs||"{}");}catch{}
    const iocDefs={ip_addresses:{label:"IP Addresses",cls:"ioc-chip"},file_hashes:{label:"File Hashes",cls:"ioc-chip ioc-hash"},domains:{label:"Domains / URLs",cls:"ioc-chip ioc-domain"}};
    let hasIOC=false;
    for(const[k,cfg] of Object.entries(iocDefs)){
      if(iocs[k]&&iocs[k].length){hasIOC=true;const g=document.createElement("div");g.innerHTML=`<div class="ioc-group-label">${cfg.label}</div><div class="ioc-chips">${iocs[k].map(v=>`<span class="${cfg.cls}">${v}</span>`).join("")}</div>`;iocEl.appendChild(g);}
    }
    if(!hasIOC)iocEl.innerHTML=`<p style="color:var(--text-muted);font-size:12px">No IOCs extracted.</p>`;
    // Status
    const sb=document.getElementById("drawer-status-badge");sb.className=`status-badge st-${{"New":"new","Triage in Progress":"triage","Automated Action Taken":"action","Resolved":"resolved"}[a.status]||"new"}`;sb.textContent=a.status;
    // Steps
    const stepsEl=document.getElementById("drawer-playbook-steps");stepsEl.innerHTML="";
    (a.playbook_steps||[]).forEach(s=>{
      const done=s.status==="Completed";
      const row=document.createElement("div");row.className="step-row";
      row.innerHTML=`<div class="step-dot ${done?"done":""}"></div><div style="flex:1"><div class="step-name">${s.step_name}</div>${done&&s.result?`<div class="step-result">${s.result}</div>`:""}</div><span class="step-status ${done?"done":"pending"}">${done?"Done":"Pending"}</span>`;
      stepsEl.appendChild(row);
    });
    // Action Buttons
    const actEl=document.getElementById("drawer-actions");actEl.innerHTML="";
    (a.playbook_steps||[]).forEach(s=>{
      const done=s.status==="Completed";
      const btn=document.createElement("button");btn.className=`play-btn${done?" done":""}`;
      btn.disabled=done||a.status==="Resolved";btn.innerHTML=`▶ ${s.step_name}`;
      if(!done&&a.status!=="Resolved")btn.onclick=()=>executeAction(s.step_name,btn);
      actEl.appendChild(btn);
    });
    // Resolve btn
    const rb=document.getElementById("btn-resolve");
    if(a.status==="Resolved"){rb.disabled=true;rb.textContent="✓ Resolved";}else{rb.disabled=false;rb.textContent="✓ Mark Resolved";}
    // Raw log
    document.getElementById("drawer-raw-log").textContent=a.raw_log||"{}";
    // Audit
    const auditEl=document.getElementById("drawer-audit");auditEl.innerHTML="";
    if(!a.audit_logs||!a.audit_logs.length){auditEl.innerHTML=`<p style="color:var(--text-muted);font-size:12px">No audit entries yet.</p>`;return;}
    a.audit_logs.forEach(l=>{
      const e=document.createElement("div");e.className="audit-entry";
      e.innerHTML=`<div class="audit-ts">${(l.timestamp||"").slice(0,19).replace("T"," ")} UTC</div><div><div class="audit-action">${l.action}</div><div class="audit-actor">by ${l.actor}</div>${l.details?`<div class="audit-detail">${l.details}</div>`:""}</div>`;
      auditEl.appendChild(e);
    });
  }catch(e){toast("Failed to load alert details.","error");}
}

function closeDrawer(){
  currentAlertId=null;
  document.getElementById("drawer-overlay").classList.remove("open");
  document.getElementById("alert-drawer").classList.remove("open");
}

/* ── ACTIONS ── */
async function executeAction(action,btn){
  btn.disabled=true;btn.textContent="Running…";
  const actor=currentUser?currentUser.name:"Analyst";
  try{
    await fetch(`${API}/api/alerts/${currentAlertId}/action`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({alert_id:currentAlertId,action,actor})});
    toast(`✓ ${action} completed`,"success");
    await refreshDrawer();loadStats();
  }catch{toast(`Error executing ${action}`,"error");btn.disabled=false;btn.textContent=`▶ ${action}`;}
}

async function resolveAlert(){
  if(!currentAlertId)return;
  try{
    await fetch(`${API}/api/alerts/${currentAlertId}/resolve`,{method:"POST"});
    toast("Alert resolved.","success");await refreshDrawer();loadStats();
  }catch{toast("Error resolving alert.","error");}
}

function copyRawLog(){navigator.clipboard.writeText(document.getElementById("drawer-raw-log").textContent).then(()=>toast("JSON copied.","success"));}

/* ── SIMULATE ── */
async function simulateAlert(){
  const sources=["CrowdStrike","SentinelOne","Okta","Palo Alto","Splunk"];
  const types=["Malware Detection","Brute Force Login","Lateral Movement","Data Exfiltration","C2 Communication"];
  const sevs=["Critical","High","Medium"];
  try{
    const r=await fetch(`${API}/api/webhook/alert`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({source:sources[Math.floor(Math.random()*sources.length)],severity:sevs[Math.floor(Math.random()*sevs.length)],alert_type:types[Math.floor(Math.random()*types.length)],title:"Simulated webhook alert from AegisGuard test tool"})});
    const d=await r.json();toast(`🔔 New alert: ${d.alert_id}`,"warn");
    setTimeout(()=>{loadDashboard();loadAlerts();},400);
  }catch{toast("Could not simulate — backend offline.","error");}
}

/* ── NOTIFICATIONS ── */
async function loadNotificationView(){await loadNotificationSettings();await loadNotificationsHistory();}

async function loadNotificationSettings(){
  try{
    const cfg=await fetch(`${API}/api/settings/notifications`).then(r=>r.json());
    if(cfg.slack_channel)document.getElementById("cfg-slack-channel").value=cfg.slack_channel;
    if(cfg.slack_webhook)document.getElementById("cfg-slack-webhook").value=cfg.slack_webhook;
    if(cfg.email_recipient)document.getElementById("cfg-email-recipient").value=cfg.email_recipient;
    if(cfg.notify_critical_only)document.getElementById("cfg-notify-critical").value=cfg.notify_critical_only;
  }catch{}
}

async function saveNotificationSettings(){
  try{
    await fetch(`${API}/api/settings/notifications`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({slack_channel:document.getElementById("cfg-slack-channel").value,slack_webhook:document.getElementById("cfg-slack-webhook").value,email_recipient:document.getElementById("cfg-email-recipient").value,notify_critical_only:document.getElementById("cfg-notify-critical").value})});
    toast("Settings saved.","success");
  }catch{toast("Failed to save.","error");}
}

async function sendTestNotification(){
  try{const d=await fetch(`${API}/api/notifications/test`,{method:"POST"}).then(r=>r.json());toast(`🔔 ${d.message}`,"success");await loadNotificationsHistory();}
  catch{toast("Failed to send test.","error");}
}

async function loadNotificationsHistory(){
  const tbody=document.getElementById("notifications-tbody");if(!tbody)return;
  try{
    const notifs=await fetch(`${API}/api/notifications`).then(r=>r.json());
    const cnt=document.getElementById("notif-count");if(cnt)cnt.textContent=`${notifs.length} dispatches`;
    if(!notifs.length){tbody.innerHTML=`<tr><td colspan="6" class="empty-cell">No notifications yet</td></tr>`;return;}
    tbody.innerHTML=notifs.map(n=>{
      let preview=n.message;try{const p=JSON.parse(n.message);if(p.text)preview=p.text;}catch{}
      return`<tr><td class="cell-ts">${(n.sent_at||"").slice(0,19).replace("T"," ")} UTC</td><td>${sourcePill(n.channel==="Slack"?"💬 Slack":"✉️ Email")}</td><td style="font-family:var(--mono);font-size:11px">${n.recipient}</td><td class="cell-id">${n.alert_id}</td><td><span class="status-badge st-resolved">${n.status}</span></td><td style="max-width:280px;white-space:normal;color:var(--text-dim);font-size:11px">${preview}</td></tr>`;
    }).join("");
  }catch{}
}

/* ── AUTO REFRESH ── */
function startAutoRefresh(){
  setInterval(()=>{
    const active=document.querySelector(".view.active");
    if(!active)return;
    if(active.id==="view-dashboard")loadDashboard();
    else if(active.id==="view-alerts")loadAlerts();
    loadStats();
  },30000);
}

/* ── INIT ── */
window.onload=()=>checkAuth();
