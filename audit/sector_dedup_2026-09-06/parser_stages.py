import sys,re,json
from pathlib import Path
p=Path(__file__).parent;sys.path.insert(0,str(p.parents[1]))
from cyberwatch.collectors import feed
from cyberwatch.collectors.wordpress import strip_html
s=(p/'sources/ITM-7a872ed42e894347.html').read_text()
for name,pat in [('dynamic',feed._DYNAMIC_BLOCK_RE),('noneditorial',feed._NON_EDITORIAL_RE)]:
 print('STAGE',name,'before',len(s))
 for m in pat.finditer(s):
  print('REMOVAL',len(m.group()),'start',repr(m.group()[:240]),'end',repr(m.group()[-100:]))
 s=pat.sub(' ',s);print('AFTER',len(s))
# Standard HTML parser only: no production edit.
from html.parser import HTMLParser
class P(HTMLParser):
 def __init__(self):super().__init__();self.skip=0;self.result=[]
 def handle_starttag(self,t,a):
  if t in ['script','style','noscript']:self.skip+=1
 def handle_endtag(self,t):
  if t in ['script','style','noscript']:self.skip=max(0,self.skip-1)
 def handle_data(self,d):
  if not self.skip and d.strip():self.result.append(d.strip())
v=P();v.feed((p/'sources/ITM-7a872ed42e894347.html').read_text());print('AVEYRON',' '.join(v.result)[:5000])
