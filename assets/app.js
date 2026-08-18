/* Cyberwatch — runtime unique du dashboard, sans dépendance externe. */
(() => {
  "use strict";

  const $ = (s) => document.querySelector(s);
  const $$ = (s) => [...document.querySelectorAll(s)];
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const norm = (v) => String(v || "").normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLocaleLowerCase("fr-FR").trim();
  const OCEAN = new Set(["La Réunion","Mayotte","Maurice","Madagascar","Seychelles","Comores"]);
  const MONTHS = ["janv.","févr.","mars","avr.","mai","juin","juil.","août","sept.","oct.","nov.","déc."];
  const SENSITIVE = ["sante","medical","patient","diagnostic","patholog","ordonnance","traitement","vaccin","nir","securite sociale","passeport","carte d identite","piece d identite","permis de conduire","biometr","selfie","mot de passe","password","hash","token","otp","secret","cle api","authent","iban","rib","bancair","carte de paiement","carte bancaire","releve de compte","revenu","salaire","patrimoine"];
  const PERSONAL = ["e-mail","email","telephone","adresse postale","date de naissance","numero client","identifiant client","coordonnees personnelles"];
  const state = { incidents: [], status: null, sort: {key:"date",dir:-1}, page: 1, pageSize: 50, filters: {ocean:false,local:false,source:"",org:""} };

  function sourceLabel(id) {
    return ({BONJOURLAFUITE:"BonjourLaFuite",FRENCHBREACHES:"FrenchBreaches",CYBERATTAQUE_ORG:"Cyberattaque.org",RANSOMWARE_LIVE:"Ransomware.live",VEILLE_LLM:"veillellmReYt",CERT_MU_ALERTS:"CERT-MU"})[id] || String(id || "Source");
  }
  function fmtDate(v) {
    if (!v) return "—";
    const d = new Date(v);
    return Number.isNaN(d.getTime()) ? String(v).slice(0,10) : d.toLocaleDateString("fr-FR", {day:"2-digit",month:"short",year:"numeric"});
  }
  function fmtNum(v) { const n = Number(v); return Number.isFinite(n) ? n.toLocaleString("fr-FR") : String(v || ""); }
  function safeUrl(v) { try { const u = new URL(v, location.href); return ["http:","https:"].includes(u.protocol) ? u.href : ""; } catch (_) { return ""; } }
  function host(v) { try { return new URL(v).hostname.replace(/^www\./, ""); } catch (_) { return "lien"; } }

  function installCss() {
    const style = document.createElement("style");
    style.textContent = `
      .dashboard-charts{margin-top:var(--gap)}.filters-toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:16px 0 4px}
      .org-search{min-width:min(320px,100%);flex:1 1 240px;font:inherit;font-size:13.5px;padding:7px 11px;border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--surface);color:var(--text-primary)}
      .btn-reset,.incident-details-toggle,.audit-pager button,.audit-pager select{font:inherit;border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--surface);color:var(--text-secondary);cursor:pointer}.btn-reset{font-size:13.5px;padding:7px 12px}.incident-details-toggle{font-size:11.5px;padding:2px 7px;margin-left:8px;border-radius:999px}
      .sort-button{all:unset;cursor:pointer;color:inherit}.sort-button:focus-visible,.btn-quick:focus-visible,.btn-reset:focus-visible,.org-search:focus-visible,.theme-toggle:focus-visible,.incident-details-toggle:focus-visible,.audit-pager button:focus-visible,.audit-pager select:focus-visible{outline:2px solid var(--series-1);outline-offset:2px}
      .incidents-card .table-scroll{max-height:none}.audit-pager{display:flex;justify-content:space-between;gap:10px;align-items:center;flex-wrap:wrap;margin-top:12px;font-size:12.5px;color:var(--text-secondary)}.audit-pager-actions{display:flex;gap:8px;align-items:center}.audit-pager button,.audit-pager select{font-size:13px;padding:6px 9px}.audit-pager button:disabled{opacity:.45}
      .sources-list{display:flex;gap:9px 18px;flex-wrap:wrap;margin-top:12px}.source-state{display:inline-flex;align-items:center;gap:7px;font-size:14px}.source-led{width:9px;height:9px;border-radius:50%;background:var(--text-muted)}.source-led--ok{background:var(--status-ok)}.source-led--attention{background:var(--status-partial)}.source-led--fail{background:var(--status-fail)}
      .sources-detail{margin-top:14px}.sources-detail>summary{cursor:pointer;font-size:13px;color:var(--text-secondary)}.sources-detail .table-scroll{margin-top:10px}
      .source-badges,.evidence-links{display:flex;gap:6px;flex-wrap:wrap}.source-badge{display:inline-flex;padding:2px 7px;border:1px solid var(--border);border-radius:999px;background:var(--plane);font-size:11.5px;text-decoration:none;color:var(--text-secondary)}.evidence-links{margin-top:6px;font-size:11.5px;color:var(--text-secondary)}
      .data-sensitivity{display:inline-flex;margin-left:7px;padding:2px 7px;border-radius:999px;border:1px solid var(--border);font-size:11px;font-weight:650}.data-sensitivity--personal{background:rgba(217,154,0,.14)}.data-sensitivity--sensitive{background:rgba(214,69,69,.14)}.data-sensitivity--unknown{color:var(--text-secondary)}
      .incident-details-row[hidden]{display:none}.incident-details-cell{white-space:normal!important;background:var(--plane);padding:12px 14px!important}.incident-details-grid,.incident-facts-list{display:grid;gap:8px}.incident-summary,.local-analysis,.incident-fact{padding:9px 10px;border:1px solid var(--border);border-radius:8px;background:var(--surface);font-size:12.5px;line-height:1.45}.incident-fact-source{font-weight:650;margin-bottom:4px}.incident-fact-row{display:flex;gap:6px;margin-top:2px}.incident-fact-label{color:var(--text-muted);flex:none}.incident-fact-value{overflow-wrap:anywhere}.incident-data-values{display:flex;gap:4px;flex-wrap:wrap;margin-top:5px}.incident-data-value{display:inline-flex;padding:2px 7px;border:1px solid var(--border);border-radius:999px}.local-score{display:inline-flex;padding:2px 7px;border:1px solid var(--border);border-radius:999px;font-weight:650}.local-analysis p{margin:6px 0 0}.bar-hit:focus{outline:none;stroke:var(--series-1);stroke-width:2}
      @media(max-width:700px){.topbar-inner{align-items:flex-start}.brand-sub{max-width:190px}.run-pill{white-space:normal;text-align:left}.incidents-card .table-scroll,.reliability .table-scroll{overflow:visible;max-height:none}#incidents-table thead,#sources-detail-table thead{display:none}#incidents-table,#incidents-table tbody,#incidents-table tr,#incidents-table td,#sources-detail-table,#sources-detail-table tbody,#sources-detail-table tr,#sources-detail-table td{display:block;width:100%}#incidents-table tr.incident-row,#sources-detail-table tr{padding:11px 0;border-bottom:1px solid var(--grid)}#incidents-table td:not(.incident-details-cell),#sources-detail-table td{border:0!important;padding:3px 0!important;white-space:normal!important;max-width:none!important}#incidents-table td[data-label]::before,#sources-detail-table td[data-label]::before{content:attr(data-label);display:inline-block;min-width:88px;margin-right:8px;color:var(--text-muted);font-size:10.5px;text-transform:uppercase}.org-cell{font-size:16px!important}.org-cell::before{display:none!important}.incident-details-row[hidden]{display:none!important}.incident-fact-row{display:block}.incident-fact-label{display:block}.audit-pager-actions{width:100%;justify-content:space-between}}
    `;
    document.head.appendChild(style);
  }

  function filtered() {
    const q = norm(state.filters.org);
    return state.incidents.filter((i) => {
      if (state.filters.source && !(i.sources || []).includes(state.filters.source)) return false;
      if (state.filters.ocean && !OCEAN.has(i.location)) return false;
      if (state.filters.local && !i.local) return false;
      if (q && !norm(i.org).includes(q)) return false;
      return true;
    });
  }

  function countBy(rows, key, dropUnknown=false) {
    const m = new Map();
    rows.forEach((r) => { const v = r[key] || "Inconnu"; if (!dropUnknown || v !== "Inconnu") m.set(v,(m.get(v)||0)+1); });
    return [...m].map(([label,value]) => ({label,value})).sort((a,b) => b.value-a.value || a.label.localeCompare(b.label,"fr"));
  }
  function monthRange(rows) {
    const keys = rows.map((r) => String(r.date || "").slice(0,7)).filter(Boolean).sort();
    if (!keys.length) return [];
    let [y,m] = keys[0].split("-").map(Number); const [ey,em] = keys.at(-1).split("-").map(Number); const out=[];
    while (y<ey || (y===ey && m<=em)) { out.push(`${y}-${String(m).padStart(2,"0")}`); if (++m>12){m=1;y++;} }
    return out;
  }

  const SVG = "http://www.w3.org/2000/svg";
  function el(name, attrs={}, text) { const n=document.createElementNS(SVG,name); Object.entries(attrs).forEach(([k,v])=>n.setAttribute(k,String(v))); if(text!==undefined)n.textContent=text; return n; }
  function tooltip(node, html, label) {
    const tip = $("#tooltip"); node.setAttribute("tabindex","0"); node.setAttribute("role","img"); node.setAttribute("aria-label",label);
    const show=(e)=>{if(!tip)return;tip.innerHTML=html;tip.hidden=false;const r=tip.getBoundingClientRect(),t=node.getBoundingClientRect(),x=e?.clientX??t.left+t.width/2,y=e?.clientY??t.top+t.height/2;tip.style.left=`${Math.max(8,Math.min(innerWidth-r.width-8,x+14))}px`;tip.style.top=`${Math.max(8,Math.min(innerHeight-r.height-8,y+14))}px`;};
    node.addEventListener("mouseenter",show); node.addEventListener("mousemove",show); node.addEventListener("focus",show); ["mouseleave","blur"].forEach((ev)=>node.addEventListener(ev,()=>{if(tip)tip.hidden=true;}));
  }
  function emptyChart(c) { if(c)c.innerHTML='<p class="empty-chart">Aucun incident sur la sélection.</p>'; }
  function barH(c,data) {
    if(!c)return;c.innerHTML="";if(!data.length)return emptyChart(c);let rows=data.length>9?data.slice(0,8).concat([{label:"Autres",value:data.slice(8).reduce((s,x)=>s+x.value,0)}]):data;
    const w=Math.max(c.clientWidth||520,320),rh=26,h=rows.length*rh+16,lw=Math.min(190,Math.max(110,w*.36)),pw=w-lw-44,max=Math.max(...rows.map(x=>x.value),1),svg=el("svg",{viewBox:`0 0 ${w} ${h}`,width:w,height:h,role:"img","aria-label":"Répartition par catégorie"});
    rows.forEach((r,i)=>{const y=i*rh+8,bw=Math.max(3,r.value/max*pw);svg.appendChild(el("text",{class:"tick-label",x:lw-10,y:y+rh/2,"text-anchor":"end","dominant-baseline":"middle"},r.label.length>26?`${r.label.slice(0,25)}…`:r.label));svg.appendChild(el("rect",{class:"bar",x:lw,y:y+5,width:bw,height:rh-12,rx:4}));svg.appendChild(el("text",{class:"value-label",x:lw+bw+8,y:y+rh/2,"dominant-baseline":"middle"},String(r.value)));const hit=el("rect",{class:"bar-hit",x:0,y,width:w,height:rh});tooltip(hit,`<strong>${esc(r.label)}</strong> ${r.value} incident${r.value>1?"s":""}`,`${r.label} : ${r.value} incidents`);svg.appendChild(hit);});c.appendChild(svg);
  }
  function barTime(c,data) {
    if(!c)return;c.innerHTML="";if(!data.length)return emptyChart(c);const w=Math.max(c.clientWidth||520,320),h=240,m={t:14,r:8,b:34,l:34},pw=w-m.l-m.r,ph=h-m.t-m.b,max=Math.max(...data.map(x=>x.value),1),step=pw/data.length,bw=Math.max(3,Math.min(38,step-6)),svg=el("svg",{viewBox:`0 0 ${w} ${h}`,width:w,height:h,role:"img","aria-label":"Incidents par mois"});
    data.forEach((p,i)=>{const bh=p.value/max*ph,x=m.l+i*step+(step-bw)/2,y=m.t+ph-bh;if(p.value)svg.appendChild(el("rect",{class:"bar",x,y,width:bw,height:bh,rx:4}));const hit=el("rect",{class:"bar-hit",x:m.l+i*step,y:m.t,width:step,height:ph}),[yy,mm]=p.label.split("-"),lab=`${MONTHS[Number(mm)-1]} ${yy.slice(2)}`;tooltip(hit,`<strong>${esc(lab)}</strong> ${p.value} incident${p.value>1?"s":""}`,`${lab} : ${p.value} incidents`);svg.appendChild(hit);const every=Math.ceil(data.length/8);if(i%every===0||i===data.length-1)svg.appendChild(el("text",{class:"tick-label",x:m.l+i*step+step/2,y:h-12,"text-anchor":"middle"},lab));});c.appendChild(svg);
  }

  function sensitivity(i) {
    const facts=Array.isArray(i.facts)?i.facts:[], values=facts.flatMap((f)=>Array.isArray(f.data_types)?f.data_types:[]).map(norm);
    if(values.some((v)=>SENSITIVE.some((m)=>v.includes(m)))) return ["sensitive","Données sensibles"];
    if(values.some((v)=>["nom","prenom","nom et prenom","nom, prenom","nom / prenom"].includes(v)||PERSONAL.some((m)=>v.includes(m)))) return ["personal","Données personnelles"];
    if(values.length||facts.some((f)=>f.affected_count!=null||f.data_volume||f.file_count!=null)) return ["unknown","Données non qualifiées"];
    return null;
  }
  function sensitivityHtml(i) { const s=sensitivity(i); return s?`<span class="data-sensitivity data-sensitivity--${s[0]}">${s[1]}</span>`:""; }
  function factRow(k,v) { return v===undefined||v===null||v===""?"":`<div class="incident-fact-row"><span class="incident-fact-label">${esc(k)} :</span><span class="incident-fact-value">${esc(v)}</span></div>`; }
  function attackFlow(v) { return Array.isArray(v)?v.map((x)=>x?.action).filter(Boolean).slice(0,5).join(" → "):""; }
  function affected(f) { if(f.affected_count_raw)return f.affected_count_raw;if(f.affected_count==null)return "";const u={people:"personnes",accounts:"comptes",users:"utilisateurs",clients:"clients",records:"enregistrements",files:"fichiers"}[f.affected_unit]||f.affected_unit||"";return `${fmtNum(f.affected_count)}${u?` ${u}`:""}`; }
  function factHtml(f) {
    const access={phishing:"Phishing",compromised_credentials:"Identifiants compromis",vulnerability_exploitation:"Exploitation d’une vulnérabilité",remote_access:"Accès distant",third_party:"Tiers compromis",malware:"Malware",other:"Autre"}[f.initial_access]||f.initial_access||"";
    const rows=[factRow("Statut",({claimed:"Revendiqué",confirmed:"Confirmé",unconfirmed:"Non confirmé",denied:"Démenti"})[f.claim_status]||f.claim_status),factRow("Acteur",f.threat_actor),factRow("Tiers impliqué",f.third_party),factRow("Vecteur d'entrée",access),factRow("Déroulé",attackFlow(f.attack_flow)),factRow("Localisation précise",f.fine_location),factRow("Données touchées",affected(f)),factRow("Volume",f.data_volume),factRow("Fichiers",f.file_count!=null?fmtNum(f.file_count):""),factRow("Vulnérabilités",Array.isArray(f.vulnerabilities)?f.vulnerabilities.join(", "):""),factRow("CVSS",f.cvss),factRow("Date d'attaque",f.attack_date?fmtDate(f.attack_date):""),factRow("Découverte",f.discovered_date?fmtDate(f.discovered_date):""),factRow("Impact",f.impact),factRow("Synthèse",f.summary),factRow("Évolution",f.evolution)].filter(Boolean);
    if(Array.isArray(f.data_types)&&f.data_types.length) rows.splice(9,0,`<div class="incident-data-values">${[...new Set(f.data_types)].map((v)=>`<span class="incident-data-value">${esc(v)}</span>`).join("")}</div>`);
    const links=[safeUrl(f.victim_website),...(f.evidence_urls||[]).map(safeUrl)].filter(Boolean).slice(0,4);if(links.length)rows.push(`<div class="evidence-links">${links.map((u)=>`<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(host(u))}</a>`).join("")}</div>`);
    return rows.length?`<div class="incident-fact"><div class="incident-fact-source">${esc(sourceLabel(f.source))}</div>${rows.join("")}</div>`:"";
  }
  function detailHtml(i) {
    const parts=[];if(i.summary)parts.push(`<div class="incident-summary"><strong>Synthèse :</strong> ${esc(i.summary)}</div>`);const facts=(i.facts||[]).map(factHtml).filter(Boolean);if(facts.length)parts.push(`<div class="incident-facts-list">${facts.join("")}</div>`);if(i.local){const refs=(i.local.references||[]).map(safeUrl).filter(Boolean).slice(0,4);parts.push(`<div class="local-analysis"><span class="local-score">Score cyberattaque : ${esc(i.local.score)}/100</span><p><strong>Analyse locale :</strong> ${esc(i.local.summary||"—")}</p>${refs.length?`<div class="evidence-links">${refs.map((u)=>`<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(host(u))}</a>`).join("")}</div>`:""}</div>`);}return parts.length?`<div class="incident-details-grid">${parts.join("")}</div>`:'<span class="muted">Aucun enrichissement supplémentaire disponible.</span>';
  }
  function sourceLinks(i) { const badges=(i.sources||[]).map((id)=>`<span class="source-badge">${esc(sourceLabel(id))}</span>`).join("");const urls=[...new Set((i.urls||[]).map(safeUrl).filter(Boolean))].slice(0,3);return `<div class="source-badges">${badges}</div>${urls.length?`<div class="evidence-links">${urls.map((u)=>`<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(host(u))}</a>`).join("")}</div>`:""}`; }

  function renderTable(rows) {
    const sorted=rows.slice().sort((a,b)=>{const k=state.sort.key,l=k==="items"?(a.sources||[]).length:(a[k]||""),r=k==="items"?(b.sources||[]).length:(b[k]||"");return l<r?-state.sort.dir:l>r?state.sort.dir:0;}),pages=Math.max(1,Math.ceil(sorted.length/state.pageSize));state.page=Math.min(state.page,pages);const start=(state.page-1)*state.pageSize,shown=sorted.slice(start,start+state.pageSize),tbody=$("#incidents-table tbody");
    tbody.innerHTML=shown.length?shown.map((i,n)=>{const id=`incident-details-${esc(i.id||`${start+n}`).replace(/[^a-zA-Z0-9_-]/g,"-")}`;return `<tr class="incident-row"><td data-label="Date" class="num">${esc(i.date||"—")}</td><td data-label="Organisation" class="wrap-cell org-cell"><strong>${esc(i.org||"Organisation inconnue")}</strong>${sensitivityHtml(i)}<button class="incident-details-toggle" type="button" aria-expanded="false" aria-controls="${id}">Détails</button></td><td data-label="Territoire">${esc(i.location||"—")}</td><td data-label="Secteur">${esc(i.sector||"—")}</td><td data-label="Menace">${esc(i.threat||"—")}</td><td data-label="Sources">${sourceLinks(i)}</td></tr><tr class="incident-details-row" id="${id}" hidden><td class="incident-details-cell" colspan="6">${detailHtml(i)}</td></tr>`;}).join(""):'<tr><td colspan="6" class="muted">Aucun incident ne correspond aux filtres.</td></tr>';
    $("#table-count").textContent=sorted.length?`${start+1}–${Math.min(start+shown.length,sorted.length)} sur ${sorted.length} incidents`:"0 incident";
    $("#audit-pager").innerHTML=`<span>Page ${state.page} / ${pages}</span><div class="audit-pager-actions"><label>Lignes <select id="audit-page-size"><option>25</option><option>50</option><option>100</option></select></label><button id="audit-prev" type="button" ${state.page<=1?"disabled":""}>Précédent</button><button id="audit-next" type="button" ${state.page>=pages?"disabled":""}>Suivant</button></div>`;$("#audit-page-size").value=String(state.pageSize);
  }

  function renderKpis(rows) { const now=new Date(),cut=new Date(now.getTime()-30*864e5);$("#kpi-incidents").textContent=rows.length;$("#kpi-30d").textContent=rows.filter((i)=>{const d=new Date(i.date);return !Number.isNaN(d.getTime())&&d>=cut&&d<=now;}).length;$("#kpi-ocean").textContent=rows.filter((i)=>OCEAN.has(i.location)).length;$("#kpi-ransomware").textContent=rows.filter((i)=>norm(i.threat).includes("ransomware")).length;$("#kpi-incidents-note").textContent=rows.length===state.incidents.length?"événements uniques dans la base":"événements correspondant aux filtres actifs"; }
  function renderCharts(rows) { const months=monthRange(rows),m=new Map();rows.forEach((i)=>{const k=String(i.date||"").slice(0,7);if(k)m.set(k,(m.get(k)||0)+1);});barTime($("#chart-month"),months.map((k)=>({label:k,value:m.get(k)||0})));barH($("#chart-location"),countBy(rows,"location"));barH($("#chart-sector"),countBy(rows,"sector",true));barH($("#chart-threat"),countBy(rows,"threat"));const known=rows.filter((i)=>(i.sector||"Inconnu")!=="Inconnu").length;$("#sector-note").textContent=rows.length?`${known} incidents sur ${rows.length} ont un secteur documenté (${Math.round(100*known/rows.length)} %).`:""; }

  function renderSources() { const rows=state.status?.sources||[],list=$("#sources-list");list.innerHTML=rows.map((s)=>{const st=String(s.status||"SKIPPED").toUpperCase(),level=st==="OK"?"ok":st==="FAIL"?"fail":"attention";return `<span class="source-state"><span class="source-led source-led--${level}" role="img" aria-label="${esc(st)}"></span>${esc(sourceLabel(s.id))}</span>`;}).join("");$("#sources-detail-table tbody").innerHTML=rows.map((s)=>`<tr><td data-label="Source">${esc(sourceLabel(s.id))}</td><td data-label="Statut"><span class="chip" data-status="${esc(String(s.status||"SKIPPED").toUpperCase())}">${esc(String(s.status||"SKIPPED").toUpperCase())}</span></td><td data-label="Dernier item">${esc(fmtDate(s.latest_item))}</td><td data-label="Organisation">${esc(s.latest_item_org||"—")}</td><td data-label="Items vus" class="num">${esc(s.items_seen??"—")}</td><td data-label="Items dans la fenêtre" class="num">${esc(s.items_in_window??"—")}</td></tr>`).join(""); }
  function renderRun() { const d=state.status,p=$("#run-pill"),t=$("#run-pill-text");if(d?.initialized===false){p.dataset.status="";t.textContent="Base non initialisée";return;}if(!d?.run?.id){p.dataset.status="";t.textContent="Aucune collecte";return;}const c=d.counts||{ok:0,partial:0,fail:0,skipped:0},total=(d.sources||[]).length||c.ok+c.partial+c.fail+c.skipped,n=(d.blind_spots||[]).length;p.dataset.status=d.run.overall;t.textContent=n?`Sources : ${c.ok}/${total} opérationnelles · ${n} à vérifier`:`Sources : ${c.ok}/${total} opérationnelles`; }
  function render() { renderRun();renderSources();if(state.status?.initialized===false)return;const rows=filtered();renderKpis(rows);renderCharts(rows);renderTable(rows); }

  function setup() {
    $("#f-ocean-indien").onclick=()=>{state.filters.ocean=!state.filters.ocean;$("#f-ocean-indien").setAttribute("aria-pressed",String(state.filters.ocean));state.page=1;render();};
    $("#f-local").onclick=()=>{state.filters.local=!state.filters.local;$("#f-local").setAttribute("aria-pressed",String(state.filters.local));state.page=1;render();};
    $("#f-source").onchange=(e)=>{state.filters.source=e.target.value||"";state.page=1;render();};let timer;$("#f-org").oninput=(e)=>{clearTimeout(timer);const v=e.target.value;timer=setTimeout(()=>{state.filters.org=v;state.page=1;render();},180);};
    $("#f-reset").onclick=()=>{state.filters={ocean:false,local:false,source:"",org:""};$("#f-ocean-indien").setAttribute("aria-pressed","false");$("#f-local").setAttribute("aria-pressed","false");$("#f-source").value="";$("#f-org").value="";state.page=1;render();};
    $$("#incidents-table th[data-sort] .sort-button").forEach((b)=>b.onclick=()=>{const th=b.closest("th"),k=th.dataset.sort;state.sort={key:k,dir:state.sort.key===k?-state.sort.dir:(k==="date"?-1:1)};$$('#incidents-table th[data-sort]').forEach((x)=>x.setAttribute("aria-sort",x===th?(state.sort.dir===1?"ascending":"descending"):"none"));state.page=1;render();});
    $("#incidents-table tbody").onclick=(e)=>{const b=e.target.closest(".incident-details-toggle");if(!b)return;const row=document.getElementById(b.getAttribute("aria-controls")),open=b.getAttribute("aria-expanded")==="true";b.setAttribute("aria-expanded",String(!open));b.textContent=open?"Détails":"Masquer";row.hidden=open;};
    $("#audit-pager").onclick=(e)=>{if(e.target.id==="audit-prev"&&state.page>1){state.page--;render();}if(e.target.id==="audit-next"){state.page++;render();}};$("#audit-pager").onchange=(e)=>{if(e.target.id==="audit-page-size"){state.pageSize=Number(e.target.value)||50;state.page=1;render();}};
    const stored=localStorage.getItem("cyberwatch-theme");if(stored)document.documentElement.dataset.theme=stored;$("#theme-toggle").onclick=()=>{const dark=document.documentElement.dataset.theme==="dark"||(!document.documentElement.dataset.theme&&matchMedia("(prefers-color-scheme: dark)").matches),next=dark?"light":"dark";document.documentElement.dataset.theme=next;localStorage.setItem("cyberwatch-theme",next);renderCharts(filtered());};let rt;addEventListener("resize",()=>{clearTimeout(rt);rt=setTimeout(()=>renderCharts(filtered()),200);});
  }

  async function load(path,fallback){try{const r=await fetch(path,{cache:"no-cache"});if(!r.ok)throw new Error(String(r.status));return await r.json();}catch(e){console.warn(`Données indisponibles : ${path}`,e);return fallback;}}
  document.addEventListener("DOMContentLoaded", async()=>{installCss();const [incidents,status]=await Promise.all([load("assets/data/incidents.json",[]),load("assets/data/status.json",null)]);state.incidents=Array.isArray(incidents)?incidents:[];state.status=status;setup();render();});
})();
