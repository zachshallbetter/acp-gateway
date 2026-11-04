#!/bin/sh
# One page, one color scheme: tools/axe-one.sh light docs/client.html
cd "$(dirname "$0")/.."
sc=$1; p=$2; prof="$PWD/.chrome-profile/axe-$sc-$(echo "$p" | tr '/.' '__')"
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless=new --disable-gpu --no-first-run --user-data-dir="$prof" \
  --window-size=1400,1000 --virtual-time-budget=60000 --dump-dom "http://localhost:8790/_axe.html?scheme=$sc&pages=$p" 2>/dev/null |
  python3 -c "import sys,re,html,json;s=sys.stdin.read();m=re.search(r'<pre id=\"out\">(.*?)</pre>',s,re.S);d=json.loads(html.unescape(m.group(1))) if m and m.group(1)!='running' else {'$p':['DID NOT FINISH']};[print('$sc', k, v if v else 'clean') for k,v in d.items()]"
