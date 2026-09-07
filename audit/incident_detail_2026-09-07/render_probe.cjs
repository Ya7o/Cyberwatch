// Exécute le vrai renderer dans un DOM minimal, sans navigateur ni réseau.
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root,'assets/dashboard-v2.js'),'utf8')
  .replace('  init();', '  globalThis.audit = {state, openIncident, ensureFacts, dataTypesHtml, statusBadge};');
const elements = new Map();
const get = key => {if (!elements.has(key)) elements.set(key,{innerHTML:'',showModal(){},scrollTop:0}); return elements.get(key);};
let calls = 0;
const context = {console:{error(){}}, URL, Intl, Date, Map, Set,
  document:{querySelector:get}, sessionStorage:{getItem(){return null;}},
  fetch:async()=>{calls++; throw new Error('simulated outage');}};
vm.createContext(context); vm.runInContext(source,context);
const a = context.audit;
(async()=>{
  await a.ensureFacts(); await a.ensureFacts();
  const outage = {fetch_calls_after_two_attempts:calls,cached_value:a.state.facts};
  const incidents=JSON.parse(fs.readFileSync(path.join(root,'assets/data/incidents.json')));
  const facts=JSON.parse(fs.readFileSync(path.join(root,'assets/data/facts.json')));
  a.state.latest=incidents; a.state.facts=facts;
  const rendered = {};
  for(const row of incidents){await a.openIncident(row.id); rendered[row.org]=get('#detail-dialog-content').innerHTML;}
  const types=Object.values(facts).flatMap(f=>f.data_types||[]);
  const dropped=[...new Set(types.filter(e=>!a.dataTypesHtml([e]).includes(e.value.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'))).map(e=>e.value))];
  const droppedOccurrences=types.filter(e=>dropped.includes(e.value)).length;
  const affectedIncidents=incidents.filter(i=>(facts[i.id]?.data_types||[]).some(e=>dropped.includes(e.value))).map(i=>i.org);
  const backendCases=JSON.parse(fs.readFileSync(path.join(__dirname,'evidence.json'))).cases;
  const syntheticHtml={};
  for(const name of ['scalar_status_inheritance','denial_only','conflicting_scalar']){
    a.state.latest=[{id:'probe',org:'Acme',sources:[]}]; a.state.facts={probe:backendCases[name]};
    await a.openIncident('probe'); syntheticHtml[name]=get('#detail-dialog-content').innerHTML;
  }
  a.state.facts={}; await a.openIncident('probe');
  outage.display=get('#detail-dialog-content').innerHTML;
  const result={outage,sector_badges:Object.fromEntries(['inferred','referenced','reported','unknown'].map(s=>[s,a.statusBadge(s)])), dropped_types:dropped,
    dropped_occurrences:droppedOccurrences, affected_incidents:affectedIncidents, syntheticHtml,
    unique_types:[...new Set(types.map(e=>e.value))].length,
    rendered};
  fs.writeFileSync(path.join(__dirname,'render_evidence.json'),JSON.stringify(result,null,2));
  console.log(JSON.stringify({...result,rendered:undefined,syntheticHtml:undefined,outage:{...outage,display:undefined}},null,2));
})();
