import sys,re,json,copy
from pathlib import Path
p=Path(__file__).parent;sys.path.insert(0,str(p.parents[1]))
from cyberwatch.collectors import feed
from cyberwatch.model import Item
from cyberwatch import dedup,duplicate_audit,dedup_ai
results=[]
for f in (p/'sources').glob('*.html'):
 html=f.read_text();matches=list(feed._DYNAMIC_BLOCK_RE.finditer(html));bad=[m for m in matches if '<main' in m.group()]
 result={'item_id':f.stem,'html_chars':len(html),'parsed_chars':len(feed.stable_frenchbreaches_detail_text(html)),'destructive_matches':[{'chars_removed':len(m.group()),'start':m.group()[:160],'end':m.group()[-120:]} for m in bad]}
 assert bad, f'Expected current parser bug missing: {f}'
 assert result['parsed_chars']<100
 results.append(result)
html='<!-- override des <style> embarqués --><main><article>Les Curistes est spécialisée dans les cures thermales.</article></main><script>safe()</script>'
assert 'cures thermales' not in feed.stable_frenchbreaches_detail_text(html)
a=Item(Item_ID='AUDIT-A',Source_ID='CYBERATTAQUE_ORG',Organisation_Raw='Example',Organisation_Key='example',Published_Date='2026-09-01')
b=Item(Item_ID='AUDIT-B',Source_ID='FRENCHBREACHES',Organisation_Raw='Example',Organisation_Key='example',Published_Date='2026-09-05')
assert dedup.decide_merge(a,b).reason_code=='INCIDENT_KEEP_TIME_GAP'
assert duplicate_audit.find_daily_llm_candidates([a],[a,b])==[]
(p/'parser_evidence.json').write_text(json.dumps(results,ensure_ascii=False,indent=2))
print('Verified: six real HTML pages lose their body; minimal HTML reproduction; 4-day soft time-gap is excluded before LLM.')
