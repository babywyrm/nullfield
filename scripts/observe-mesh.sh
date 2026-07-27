#!/usr/bin/env bash
# Show what the mesh arbiter is actually doing, from inside the cluster.
#
# Run this ON the cluster node (or anywhere with kubectl pointed at it). Every
# view below answers a question the prose cannot: is the filter really in the
# chain, is identity really arriving, what did nullfield really decide.
#
#   ./scripts/observe-mesh.sh              # all views, once
#   ./scripts/observe-mesh.sh chain        # one view
#   ./scripts/observe-mesh.sh follow       # live tail of decisions
#   ./scripts/observe-mesh.sh send         # generate traffic to look at
#   NS=zerotrust ./scripts/observe-mesh.sh # a different namespace
#
# To watch it work: run `follow` in one terminal and `send` in another.
#
# Waypoint pods are distroless: there is no curl inside them. Envoy's admin
# interface is reached with `pilot-agent request GET <path>` instead, which is
# the single most useful thing to know when debugging one of these.

set -uo pipefail

NS="${NS:-nullfield-mesh-demo}"
WAYPOINT="${WAYPOINT:-mesh-demo-waypoint}"
ARBITER="${ARBITER:-nullfield-extauthz}"
CLIENT="${CLIENT:-mesh-demo-client}"
SVC="${SVC:-mcp-echo}"
VIEW="${1:-all}"

have() { command -v "$1" >/dev/null 2>&1; }
hdr() { printf '\n\033[1m== %s\033[0m\n%s\n' "$1" "${2:-}"; }

# ---------------------------------------------------------------- chain ----
# The identity bridge is a deployment-time property: without the Lua filter
# sitting before ext_authz, nullfield attests nothing and says so quietly.
# This is how you confirm it is really there, in the order that matters.
view_chain() {
  hdr "Filter chain on the waypoint" \
      "Lua must appear BEFORE ext_authz, or identity never arrives."
  kubectl -n "$NS" exec "deploy/$WAYPOINT" -- \
    pilot-agent request GET 'config_dump?resource=dynamic_listeners' 2>/dev/null \
  | python3 -c '
import json,sys
try: d=json.load(sys.stdin)
except Exception: print("  could not read config_dump"); sys.exit(0)
seen=set()
for c in d.get("configs",[]):
    l=c.get("active_state",{}).get("listener",{})
    for fc in l.get("filter_chains",[]):
        for f in fc.get("filters",[]):
            hcm=f.get("typed_config",{})
            if "http_filters" not in hcm: continue
            key=l.get("name","?")
            if key in seen: continue
            seen.add(key)
            print(f"\n  listener: {key}")
            for i,hf in enumerate(hcm["http_filters"],1):
                n=hf.get("name","?")
                t=hf.get("typed_config",{}).get("@type","").split(".")[-1]
                note=""
                if t=="Lua":      note="   <-- injects x-nullfield-peer-principal"
                if t=="ExtAuthz": note="   <-- asks nullfield"
                print(f"    {i:2}. {n:<44} {t}{note}")
'
}

# --------------------------------------------------------------- counts ----
# Envoy'\''s own tally, which is the tiebreaker when nullfield'\''s log and the
# observed behaviour disagree. `denied` here but nothing in nullfield'\''s log
# means Envoy refused before asking - almost always a body-size 413.
view_counters() {
  hdr "Envoy ext_authz counters" \
      "Envoy's tally. Disagreement with nullfield's log is the interesting case."
  kubectl -n "$NS" exec "deploy/$WAYPOINT" -- pilot-agent request GET stats 2>/dev/null \
    | grep -E '\.ext_authz\.|rbac\.istio_ext_authz' | grep -vE ': 0$' \
    | sed 's/^/  /' || echo "  (all counters zero - no traffic yet)"
  echo
  echo "  ok        = allowed by the decision service"
  echo "  denied    = refused by it"
  echo "  error     = it was unreachable; failure_mode_allow decided instead"
  echo "  shadow_*  = the policy is in dry-run, nothing was enforced"
}

# ------------------------------------------------------------ decisions ----
view_decisions() {
  hdr "Recent decisions" "One line per mediated call, with provenance."
  local raw; raw=$(kubectl -n "$NS" logs "deploy/$ARBITER" --tail=200 2>/dev/null | grep arbiter.decision)
  [ -z "$raw" ] && { echo "  no decisions yet - send traffic, then re-run"; return; }
  printf '%s\n' "$raw" | python3 -c '
import json,re,sys
# The provenance fields are not at the top level. The log line is a slog record
# whose "payload" is the audit event re-encoded as a JSON *string*, so a naive
# top-level read finds no principal and reports a phantom identity gap. Merge
# the inner object over the outer one.
rows=[]
for line in sys.stdin:
    m=re.search(r"\{.*\}", line)
    if not m: continue
    try: d=json.loads(m.group(0))
    except Exception: continue
    inner=d.get("payload")
    if isinstance(inner,str):
        try: d={**d, **json.loads(inner)}
        except Exception: pass
    rows.append(d)
if not rows: print("  (no parseable decisions)"); sys.exit(0)
# The taxonomy is single letters on the wire; spell them out when reading.
TRANSPORT={"A":"mcp","B":"wire-api","C":"sdk","D":"subprocess","E":"model-fn"}
w="{:<18} {:<10} {:<13} {:<10} {}"
print("  "+w.format("TOOL","TRANSPORT","REASON","ASSURANCE","PRINCIPAL"))
for d in rows[-12:]:
    t=d.get("transport") or ""
    print("  "+w.format(
        (d.get("tool_name") or "-")[:18],
        TRANSPORT.get(t,t or "-")[:10],
        (d.get("reason_class") or "-")[:13],
        (d.get("assurance") or "-")[:10],
        (d.get("workload_principal") or "-").replace("spiffe://cluster.local/","")[:44]))
# A counterfactual means the decision was NOT applied, so these rows are from
# observe or no-op. Only the non-ALLOW ones would have changed the outcome,
# which is the number worth quoting before turning enforcement on.
cf=[d for d in rows if d.get("counterfactual")]
if cf:
    blocking=[d for d in cf if d["counterfactual"] != "ALLOW"]
    print(f"\n  {len(cf)} decision(s) recorded but not applied (observe/no-op).")
    if blocking:
        print(f"  {len(blocking)} would have changed the outcome under enforce:")
        for d in blocking[-5:]:
            tn = d.get("tool_name") or "-"
            print("    " + tn.ljust(20) + " -> " + d["counterfactual"])
    else:
        print("  none of them would have been blocked.")
missing=[d for d in rows if not d.get("workload_principal")]
if missing:
    print(f"\n  {len(missing)} of {len(rows)} decision(s) carry NO principal.")
    print("  Check the Lua filter is before ext_authz (`chain`), and that the")
    print("  EnvoyFilter exists (`identity`). Both must hold for attestation.")
else:
    print(f"\n  all {len(rows)} decision(s) attributed to a caller.")
'
}

# --------------------------------------------------------------- follow ----
# Same parse as `decisions`, but streaming. Run this in one terminal and `send`
# in another to watch calls being mediated as they happen.
view_follow() {
  hdr "Following decisions (Ctrl-C to stop)" \
      "Run '$0 send' in another terminal to generate traffic."
  kubectl -n "$NS" logs -f "deploy/$ARBITER" --tail=0 2>/dev/null \
  | grep --line-buffered arbiter.decision \
  | python3 -u -c '
import json,re,sys
TRANSPORT={"A":"mcp","B":"wire-api","C":"sdk","D":"subprocess","E":"model-fn"}
w="{:<18} {:<9} {:<13} {:<9} {}"
print("  "+w.format("TOOL","TRANSPORT","REASON","ASSURANCE","PRINCIPAL"),flush=True)
for line in sys.stdin:
    m=re.search(r"\{.*\}", line)
    if not m: continue
    try: d=json.loads(m.group(0))
    except Exception: continue
    inner=d.get("payload")
    if isinstance(inner,str):
        try: d={**d, **json.loads(inner)}
        except Exception: pass
    cf=d.get("counterfactual") or ""
    # A counterfactual means this decision was not applied. Seeing one next to
    # a request that was actually blocked means the arbiter predates the fix
    # that scoped this field to observe and no-op.
    tag="   not-applied:"+cf if cf else ""
    who=(d.get("workload_principal") or "-").replace("spiffe://cluster.local/ns/","")
    print("  "+w.format(
        (d.get("tool_name") or "-")[:18],
        TRANSPORT.get(d.get("transport",""),d.get("transport") or "-")[:9],
        (d.get("reason_class") or "-")[:13],
        (d.get("assurance") or "-")[:9],
        who[:42]+tag),
        flush=True)
'
}

# ----------------------------------------------------------------- send ----
# Benign calls only. The point is to watch mediation happen, and the demo
# policy already distinguishes an allowed tool from a denied one.
view_send() {
  hdr "Sending test traffic" "Each call is mediated by the waypoint before it reaches $SVC."
  for tool in echo get_weather; do
    body="{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"$tool\",\"arguments\":{}}}"
    code=$(kubectl -n "$NS" exec "$CLIENT" -- curl -s -o /dev/null -w '%{http_code}' \
      --max-time 10 -X POST "http://$SVC/mcp" \
      -H 'Content-Type: application/json' -d "$body" 2>/dev/null)
    case "$code" in
      200) note="allowed through" ;;
      403) note="blocked by nullfield (enforce mode)" ;;
      "")  note="no response - is $CLIENT running?" ;;
      *)   note="" ;;
    esac
    printf '  %-14s HTTP %-4s %s\n' "$tool" "${code:-???}" "$note"
  done
  echo
  echo "  Now look at the decisions:  $0 decisions"
}

# ------------------------------------------------------------- identity ----
# ztunnel always knows the peer. If ztunnel shows an identity and nullfield
# does not, the mesh is healthy and the bridge is what is broken - which is a
# completely different repair from "mTLS is not working".
view_identity() {
  hdr "Identity at L4 (ztunnel)" \
      "ztunnel always knows the peer. If it does and nullfield doesn't, the bridge is at fault."
  kubectl -n istio-system logs ds/ztunnel --tail=400 2>/dev/null \
    | grep -oE 'src\.identity="[^"]+"' | sort | uniq -c | sort -rn | head -6 | sed 's/^/  /' \
    || echo "  (no ztunnel identity lines)"
  echo
  hdr "The EnvoyFilter that bridges it" ""
  kubectl -n "$NS" get envoyfilter -o custom-columns=NAME:.metadata.name --no-headers 2>/dev/null \
    | sed 's/^/  /' || echo "  none - identity will be absent"
}

# ---------------------------------------------------------------- kiali ----
view_kiali() {
  hdr "Graphical view" "Kiali draws the waypoint and the traffic through it."
  if kubectl -n istio-system get svc kiali >/dev/null 2>&1; then
    cat <<EOF
  kubectl -n istio-system port-forward svc/kiali 20001:20001
  then open  http://localhost:20001

  Graph > namespace '$NS' > Display > check 'Waypoint proxies'.
  The waypoint appears as a node every request passes through; nullfield does
  not appear in the graph at all, because it is not in the data path. Its
  effect shows as 403s on the edge into the destination.
EOF
  else
    echo "  kiali not installed"
  fi
  if kubectl -n istio-system get svc prometheus >/dev/null 2>&1; then
    cat <<EOF

  kubectl -n istio-system port-forward svc/prometheus 9090:9090
  then query:
    istio_requests_total{destination_service=~".*$NS.*",response_code="403"}
    envoy_http_ext_authz_denied
EOF
  fi
}

case "$VIEW" in
  chain)     view_chain ;;
  counters)  view_counters ;;
  decisions) view_decisions ;;
  follow)    view_follow ;;
  send)      view_send ;;
  identity)  view_identity ;;
  kiali)     view_kiali ;;
  all)       view_chain; view_counters; view_decisions; view_identity; view_kiali ;;
  *) echo "usage: $0 [chain|counters|decisions|follow|send|identity|kiali|all]"; exit 2 ;;
esac
echo
