#!/bin/sh
# Runs axe-core (WCAG 2.0 A/AA plus best practices) on each page in headless Chrome, light and dark, six at a time.
# Needs the preview server on 8790 serving dist/.
cd "$(dirname "$0")/.."
cp tools/axe-harness.html dist/_axe.html
PAGES="index.html install.html coverage.html docs.html credits.html 404.html docs/client.html docs/gateway.html docs/commitment-assurance.html docs/protected-effects.html docs/hcml-authority.html docs/gateway-github-app.html docs/icp.html docs/esp.html docs/pdp.html docs/iepe.html docs/eqp.html docs/acpr.html"
for sc in light dark; do for p in $PAGES; do echo "$sc $p"; done; done | xargs -P 6 -n 2 tools/axe-one.sh | sort
rm -f dist/_axe.html
