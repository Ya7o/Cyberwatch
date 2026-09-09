// Execute the production renderer on both immutable snapshots, offline.
const fs=require('node:fs'), vm=require('node:vm'), path=require('node:path');
const root=path.resolve(__dirname,'../..');
const source=fs.readFileSync(path.join(root,'assets/dashboard-v2.js'),'utf8').replace('  init();','  globalThis.audit = {state, openIncident, dataTypesHtml, statusBadge};');
const elements=new Map();const get=k=>{if(!elements.has(k))elements.set(k,{innerHTML:'',showModal(){},scrollTop:0});return elements.get(k);};
const context={console,URL,Intl,Date,Map,Set,document:{querySelector:get},sessionStorage:{getItem(){return null;}},fetch:async()=>{throw Error('Network forbidden in audit')}};
vm.createContext(context);vm.runInContext(source,context);const a=context.audit;
const escape=s=>s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
(async()=>{for(const run of ['run1','run2']){
 const dir=path.join(__dirname,'snapshots',run,'assets/data');
 const incidents=JSON.parse(fs.readFileSync(path.join(dir,'incidents.json'))), facts=JSON.parse(fs.readFileSync(path.join(dir,'facts.json')));
 a.state.latest=incidents;a.state.facts=facts;const rendered={};let droppedCount=0,scalarProofs=0,countProofs=0;
 for(const i of incidents){await a.openIncident(i.id);const html=get('#detail-dialog-content').innerHTML;
  const dropped=(facts[i.id]?.data_types||[]).filter(e=>!a.dataTypesHtml([e]).includes(escape(e.value))).map(e=>e.value);
  droppedCount+=dropped.length; scalarProofs+=Object.values(facts[i.id]?.fields||{}).filter(f=>f.evidence).length;
  countProofs+=(facts[i.id]?.affected||[]).filter(f=>f.evidence).length;
  rendered[i.id]={org:i.org,html,text:html.replace(/<[^>]*>/g,' ').replace(/\s+/g,' ').trim(),dropped_types:dropped};
 }
 const result={run,incidents:incidents.length,droppedCount,scalarProofs,countProofs,sectorBadges:Object.fromEntries(['inferred','referenced','reported','unknown'].map(s=>[s,a.statusBadge(s)])),rendered};
 fs.writeFileSync(path.join(__dirname,run+'_render.json'),JSON.stringify(result,null,2));
 console.log(JSON.stringify({...result,rendered:undefined}));
}})().catch(e=>{console.error(e);process.exitCode=1});
