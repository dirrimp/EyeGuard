#!/bin/sh
# Low-priority connection logger (read-only; no firewall changes). Started by /etc/init.d/connlog under nice.
# Logs NEW and DESTROY conntrack events for tcp/udp to non-private destinations.
# Format: <epoch> <N|D> <proto> <src> <dst> <dport> <bytes(D only, both directions)>
# Ring of 4 files x 50000 lines in tmpfs (/tmp/connlog/log.0-3); never touches flash.
D=/tmp/connlog
mkdir -p "$D"; chmod 700 "$D"
conntrack -E -e NEW,DESTROY -o timestamp 2>/dev/null | awk -v D="$D" '
function priv(a){ return a ~ /^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.|22[4-9]\.|23[0-9]\.|255\.|f[cd]|fe80|ff|::1)/ }
{
  ev=$2; if (ev!="[NEW]" && ev!="[DESTROY]") next
  p=$3; if (p!="tcp" && p!="udp") next
  s=""; d=""; dp=""; b=0
  for (i=4;i<=NF;i++) {
    split($i,kv,"="); k=kv[1]
    if (k=="src" && s=="") s=kv[2]
    else if (k=="dst" && d=="") d=kv[2]
    else if (k=="dport" && dp=="") dp=kv[2]
    else if (k=="bytes") b+=kv[2]
  }
  if (d=="" || priv(d) || dp==123) next
  ts=int(substr($1,2))
  if (n%50000==0) { if (f!="") close(f); f=D "/log." (int(n/50000)%4) }
  n++
  print ts, (ev=="[NEW]"?"N":"D"), p, s, d, dp, (ev=="[NEW]"?0:b) > f
  fflush(f)
}'
