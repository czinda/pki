#!/bin/bash
#
# CA Security Domain Regression Test
#
# Tests the Quarkus CA security domain REST endpoints:
#   GET /ca/v2/securityDomain/domainInfo
#   GET /ca/v2/securityDomain/hosts
#   GET /ca/v2/securityDomain/hosts/{hostId}
#
# Usage: ./test_security_domain.sh [hostname] [port]
#   hostname  - CA server hostname (default: $(hostname))
#   port      - CA secure port (default: 8443)
#

set -euo pipefail

HOST="${1:-$(hostname)}"
PORT="${2:-8443}"
BASE_URL="https://${HOST}:${PORT}/ca/v2/securityDomain"

PASS=0
FAIL=0

echo "============================================"
echo "CA Security Domain Regression Test"
echo "============================================"
echo "Target: ${BASE_URL}"
echo ""

# ----------------------------------------------------------
# Test 1: Domain Info
# ----------------------------------------------------------
echo "--- Test 1: Domain Info ---"
RESPONSE=$(curl -sk "${BASE_URL}/domainInfo")

if [ -z "$RESPONSE" ]; then
    echo "FAIL: Empty response from domainInfo endpoint"
    FAIL=$((FAIL + 1))
else
    python3 -c "
import sys, json

raw = '''${RESPONSE}'''
d = json.loads(raw)

errors = []

# Verify 'id' field (domain name) - NOT 'name'
# DomainInfo.java uses @JsonProperty('id') for the name field
if 'id' not in d:
    errors.append(f'Missing \"id\" field. Keys: {list(d.keys())}')
else:
    print(f'  Domain name (id): {d[\"id\"]}')

# Verify 'subsystems' map
if 'subsystems' not in d:
    errors.append(f'Missing \"subsystems\" field. Keys: {list(d.keys())}')
else:
    subs = d['subsystems']
    print(f'  Subsystems: {list(subs.keys())}')

    # Verify CA subsystem exists
    if 'CA' not in subs:
        errors.append(f'Missing CA subsystem. Found: {list(subs.keys())}')
    else:
        ca = subs['CA']
        # SecurityDomainSubsystem uses 'hosts' map (no @JsonProperty rename)
        if 'hosts' not in ca:
            errors.append(f'CA subsystem missing \"hosts\" map. Keys: {list(ca.keys())}')
        elif len(ca['hosts']) == 0:
            errors.append('CA subsystem has no hosts')
        else:
            print(f'  CA hosts: {len(ca[\"hosts\"])}')

    # Report all subsystem host counts
    for name, sub in subs.items():
        if isinstance(sub, dict) and 'hosts' in sub:
            print(f'    {name}: {len(sub[\"hosts\"])} host(s)')

if errors:
    for e in errors:
        print(f'  ERROR: {e}')
    sys.exit(1)
else:
    print('  Result: PASS')
" && PASS=$((PASS + 1)) || FAIL=$((FAIL + 1))
fi
echo ""

# ----------------------------------------------------------
# Test 2: Hosts List
# ----------------------------------------------------------
echo "--- Test 2: Hosts List ---"
RESPONSE=$(curl -sk "${BASE_URL}/hosts")

if [ -z "$RESPONSE" ]; then
    echo "FAIL: Empty response from hosts endpoint"
    FAIL=$((FAIL + 1))
else
    python3 -c "
import sys, json

raw = '''${RESPONSE}'''
data = json.loads(raw)

errors = []

# Endpoint returns Collection<SecurityDomainHost> - should be a JSON array
if not isinstance(data, list):
    errors.append(f'Expected JSON array, got {type(data).__name__}')
elif len(data) == 0:
    errors.append('No hosts found')
else:
    print(f'  Total hosts: {len(data)}')
    for h in data:
        # SecurityDomainHost fields:
        #   id       - no @JsonProperty, serialized as 'id'
        #   Hostname - @JsonProperty('Hostname')
        #   SecurePort - @JsonProperty('SecurePort')
        if 'id' not in h:
            errors.append(f'Host missing \"id\" field: {list(h.keys())}')
        if 'Hostname' not in h:
            errors.append(f'Host missing \"Hostname\" field: {list(h.keys())}')
        if 'SecurePort' not in h:
            errors.append(f'Host missing \"SecurePort\" field: {list(h.keys())}')
        host_id = h.get('id', '?')
        hostname = h.get('Hostname', '?')
        port = h.get('SecurePort', '?')
        print(f'    {host_id} -> {hostname}:{port}')

if errors:
    for e in errors:
        print(f'  ERROR: {e}')
    sys.exit(1)
else:
    print('  Result: PASS')
" && PASS=$((PASS + 1)) || FAIL=$((FAIL + 1))
fi
echo ""

# ----------------------------------------------------------
# Test 3: Individual Host
# ----------------------------------------------------------
echo "--- Test 3: Individual Host ---"

# Get the first host ID from the hosts list
HOST_ID=$(curl -sk "${BASE_URL}/hosts" | python3 -c "
import sys, json
data = json.loads(sys.stdin.read())
if isinstance(data, list) and len(data) > 0:
    print(data[0]['id'])
else:
    sys.exit(1)
" 2>/dev/null)

if [ -z "$HOST_ID" ]; then
    echo "  SKIP: Could not determine host ID from hosts list"
    echo ""
else
    # URL-encode the host ID (it contains spaces, e.g. "CA hostname 8443")
    ENCODED_HOST_ID=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${HOST_ID}', safe=''))")
    RESPONSE=$(curl -sk "${BASE_URL}/hosts/${ENCODED_HOST_ID}")

    if [ -z "$RESPONSE" ]; then
        echo "FAIL: Empty response for host ${HOST_ID}"
        FAIL=$((FAIL + 1))
    else
        python3 -c "
import sys, json

raw = '''${RESPONSE}'''
h = json.loads(raw)

errors = []

expected_id = '${HOST_ID}'
if h.get('id') != expected_id:
    errors.append(f'Expected id \"{expected_id}\", got \"{h.get(\"id\")}\"')

if 'Hostname' not in h:
    errors.append('Missing Hostname field')
if 'SecurePort' not in h:
    errors.append('Missing SecurePort field')

print(f'  Host ID: {h.get(\"id\")}')
print(f'  Hostname: {h.get(\"Hostname\")}')
print(f'  SecurePort: {h.get(\"SecurePort\")}')
print(f'  SecureAdminPort: {h.get(\"SecureAdminPort\", \"N/A\")}')
print(f'  SecureAgentPort: {h.get(\"SecureAgentPort\", \"N/A\")}')
print(f'  DomainManager: {h.get(\"DomainManager\", \"N/A\")}')
print(f'  Clone: {h.get(\"Clone\", \"N/A\")}')

if errors:
    for e in errors:
        print(f'  ERROR: {e}')
    sys.exit(1)
else:
    print('  Result: PASS')
" && PASS=$((PASS + 1)) || FAIL=$((FAIL + 1))
    fi
    echo ""
fi

# ----------------------------------------------------------
# Summary
# ----------------------------------------------------------
TOTAL=$((PASS + FAIL))
echo "============================================"
echo "Results: ${PASS}/${TOTAL} passed, ${FAIL} failed"
echo "============================================"

if [ "$FAIL" -gt 0 ]; then
    echo "OVERALL: FAIL"
    exit 1
else
    echo "OVERALL: PASS"
    exit 0
fi
