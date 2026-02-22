#!/bin/bash
#
# Quarkus CA/KRA Comprehensive Regression Test Suite
#
# Tests all major REST endpoints for the Quarkus CA and KRA subsystems.
# Covers public endpoints, authenticated endpoints, certificate enrollment,
# agent approval, and KRA key operations.
#
# Usage: ./test_quarkus_regression.sh [hostname] [ca_port] [kra_port] [admin_password]
#   hostname        - Server hostname (default: $(hostname))
#   ca_port         - CA secure port (default: 8443)
#   kra_port        - KRA secure port (default: 8543)
#   admin_password  - caadmin password (default: read from password.conf)
#

set -uo pipefail

HOST="${1:-$(hostname)}"
CA_PORT="${2:-8443}"
KRA_PORT="${3:-8543}"
ADMIN_PW="${4:-}"

CA_BASE="https://${HOST}:${CA_PORT}/ca"
KRA_BASE="https://${HOST}:${KRA_PORT}/kra"

PASS=0
FAIL=0
SKIP=0
TEST_NUM=0

# Try to read admin password from common locations if not provided
# The admin password is typically the internaldb password (LDAP bind password)
if [ -z "$ADMIN_PW" ]; then
    for pwfile in /etc/pki/pki-quarkus/password.conf \
                  /var/lib/pki/pki-quarkus/conf/password.conf \
                  /etc/pki/pki-tomcat/password.conf \
                  /var/lib/pki/pki-tomcat/conf/password.conf; do
        if [ -f "$pwfile" ]; then
            # Prefer internaldb password (used for admin auth)
            ADMIN_PW=$(grep -E '^internaldb=' "$pwfile" 2>/dev/null | cut -d= -f2-)
            if [ -n "$ADMIN_PW" ]; then
                break
            fi
        fi
    done
fi

# Client cert auth (if available)
CLIENT_CERT=""
for certfile in /root/.dogtag/pki-tomcat/ca_admin_cert.pem \
                /root/.dogtag/pki-quarkus/ca_admin_cert.pem \
                /var/lib/pki/pki-tomcat/ca_admin_cert.pem; do
    if [ -f "$certfile" ]; then
        CLIENT_CERT="--cert ${certfile}"
        break
    fi
done

NSSDB=""
for nssdir in /root/.dogtag/nssdb /root/.dogtag/pki-tomcat/nssdb; do
    if [ -d "$nssdir" ]; then
        NSSDB="$nssdir"
        break
    fi
done

echo "============================================"
echo "Quarkus CA/KRA Regression Test Suite"
echo "============================================"
echo "Target: CA=${CA_BASE}  KRA=${KRA_BASE}"
if [ -n "$ADMIN_PW" ]; then
    echo "Auth: basic auth configured"
else
    echo "Auth: NO basic auth"
fi
echo "Date: $(date)"
echo ""

# Helper: curl with optional basic auth
# Usage: do_curl [--auth] [--kra-auth] [curl_args...]
do_curl() {
    local auth_user=""
    if [ "${1:-}" = "--auth" ]; then
        auth_user="caadmin"
        shift
    elif [ "${1:-}" = "--kra-auth" ]; then
        auth_user="kraadmin"
        shift
    fi
    if [ -n "$auth_user" ] && [ -n "$ADMIN_PW" ]; then
        curl -sk -u "${auth_user}:${ADMIN_PW}" "$@"
    else
        curl -sk "$@"
    fi
}

run_test() {
    local test_name="$1"
    local url="$2"
    local validation="$3"
    local use_auth="${4:-false}"

    TEST_NUM=$((TEST_NUM + 1))
    printf "  [%02d] %-50s " "$TEST_NUM" "$test_name"

    local auth_flag=""
    if [ "$use_auth" = "true" ]; then
        auth_flag="--auth"
    elif [ "$use_auth" = "kra" ]; then
        auth_flag="--kra-auth"
    fi

    RESPONSE=$(do_curl $auth_flag "$url" 2>/dev/null)
    HTTP_CODE=$(do_curl $auth_flag -o /dev/null -w '%{http_code}' "$url" 2>/dev/null)

    if [ -z "$RESPONSE" ] && [ "$HTTP_CODE" = "000" ]; then
        echo "FAIL (no response)"
        FAIL=$((FAIL + 1))
        return 1
    fi

    if [ "$HTTP_CODE" = "401" ]; then
        echo "FAIL (HTTP 401 Unauthorized)"
        FAIL=$((FAIL + 1))
        return 1
    fi

    if [ "$HTTP_CODE" = "404" ]; then
        echo "FAIL (HTTP 404 Not Found)"
        FAIL=$((FAIL + 1))
        return 1
    fi

    if echo "$RESPONSE" | python3 -c "$validation" 2>/dev/null; then
        echo "PASS (HTTP $HTTP_CODE)"
        PASS=$((PASS + 1))
        return 0
    else
        echo "FAIL (HTTP $HTTP_CODE)"
        echo "       Response: $(echo "$RESPONSE" | head -c 200)"
        FAIL=$((FAIL + 1))
        return 1
    fi
}

run_test_http_code() {
    local test_name="$1"
    local method="$2"
    local url="$3"
    local expected_code="$4"
    local use_auth="${5:-false}"

    TEST_NUM=$((TEST_NUM + 1))
    printf "  [%02d] %-50s " "$TEST_NUM" "$test_name"

    local auth_flag=""
    if [ "$use_auth" = "true" ]; then
        auth_flag="--auth"
    fi

    HTTP_CODE=$(do_curl $auth_flag -X "$method" -o /dev/null -w '%{http_code}' "$url" 2>/dev/null)

    if [ "$HTTP_CODE" = "$expected_code" ]; then
        echo "PASS (HTTP $HTTP_CODE)"
        PASS=$((PASS + 1))
        return 0
    else
        echo "FAIL (expected $expected_code, got $HTTP_CODE)"
        FAIL=$((FAIL + 1))
        return 1
    fi
}

skip_test() {
    local test_name="$1"
    local reason="$2"

    TEST_NUM=$((TEST_NUM + 1))
    printf "  [%02d] %-50s SKIP (%s)\n" "$TEST_NUM" "$test_name" "$reason"
    SKIP=$((SKIP + 1))
}


# ===========================================================
echo "--- CA Public Endpoints ---"
echo ""
# ===========================================================

run_test "CA Info" \
    "${CA_BASE}/v2/info" \
    "
import sys, json
d = json.load(sys.stdin)
assert len(d) > 0, 'Empty info'
"

run_test "Security Domain - domainInfo" \
    "${CA_BASE}/v2/securityDomain/domainInfo" \
    "
import sys, json
d = json.load(sys.stdin)
assert 'id' in d, 'Missing id'
assert 'subsystems' in d, 'Missing subsystems'
assert 'CA' in d['subsystems'], 'Missing CA subsystem'
"

run_test "Security Domain - hosts" \
    "${CA_BASE}/v2/securityDomain/hosts" \
    "
import sys, json
hosts = json.load(sys.stdin)
assert isinstance(hosts, list), 'Expected array'
assert len(hosts) > 0, 'No hosts'
assert 'id' in hosts[0], 'Missing id field'
assert 'Hostname' in hosts[0], 'Missing Hostname'
"

run_test "Certificate List (v2/certs)" \
    "${CA_BASE}/v2/certs" \
    "
import sys, json
d = json.load(sys.stdin)
assert isinstance(d, (list, dict)), 'Unexpected type'
"

run_test "Enrollment Profiles (v2/certrequests/profiles)" \
    "${CA_BASE}/v2/certrequests/profiles" \
    "
import sys, json
d = json.load(sys.stdin)
assert isinstance(d, (list, dict)), 'Unexpected type'
"

run_test "CA Certificate Chain" \
    "${CA_BASE}/ee/ca/getCertChain" \
    "
import sys, json
d = json.load(sys.stdin)
assert len(d) > 0, 'No cert chain'
"

run_test_http_code "OCSP Responder (POST, expect 400 w/o body)" \
    "POST" "${CA_BASE}/ocsp" "400"

run_test "CA Chain (ee/ca/getCAChain)" \
    "${CA_BASE}/ee/ca/getCAChain" \
    "
import sys
data = sys.stdin.read()
assert len(data) > 10, 'Empty response'
"

run_test "CA Status (admin/ca/getStatus)" \
    "${CA_BASE}/admin/ca/getStatus" \
    "
import sys
data = sys.stdin.read()
assert len(data) > 10, 'Empty status'
assert 'resource not found' not in data.lower(), '404 response'
"

echo ""

# ===========================================================
echo "--- CA Authenticated Endpoints ---"
echo ""
# ===========================================================

if [ -n "$ADMIN_PW" ]; then

    run_test "Account Login" \
        "${CA_BASE}/v2/account/login" \
        "
import sys, json
d = json.load(sys.stdin)
assert len(d) > 0, 'No account data'
" "true"

    run_test "Profile List (v2/profiles)" \
        "${CA_BASE}/v2/profiles" \
        "
import sys, json
d = json.load(sys.stdin)
assert isinstance(d, (list, dict)), 'Unexpected type'
" "true"

    run_test "Get caUserCert Profile" \
        "${CA_BASE}/v2/profiles/caUserCert" \
        "
import sys, json
d = json.load(sys.stdin)
assert len(d) > 0, 'No profile data'
" "true"

    run_test "Agent Cert Requests List" \
        "${CA_BASE}/v2/agent/certrequests" \
        "
import sys, json
d = json.load(sys.stdin)
assert isinstance(d, (list, dict)), 'Unexpected type'
" "true"

    run_test "Audit Configuration" \
        "${CA_BASE}/v2/audit" \
        "
import sys, json
d = json.load(sys.stdin)
assert isinstance(d, dict), 'Expected object'
assert len(d) > 0, 'Empty audit config'
" "true"

    run_test "Admin Users List" \
        "${CA_BASE}/v2/admin/users" \
        "
import sys, json
d = json.load(sys.stdin)
assert isinstance(d, (list, dict)), 'Unexpected type'
" "true"

    run_test "Admin Groups List" \
        "${CA_BASE}/v2/admin/groups" \
        "
import sys, json
d = json.load(sys.stdin)
assert isinstance(d, (list, dict)), 'Unexpected type'
" "true"

    run_test "Self Tests List" \
        "${CA_BASE}/v2/selftests" \
        "
import sys, json
d = json.load(sys.stdin)
assert isinstance(d, (list, dict)), 'Unexpected type'
" "true"

    run_test "Authorities List (sub-CAs)" \
        "${CA_BASE}/v2/authorities" \
        "
import sys, json
d = json.load(sys.stdin)
assert isinstance(d, (list, dict)), 'Unexpected type'
" "true"

    run_test "Config Features" \
        "${CA_BASE}/v2/config/features" \
        "
import sys, json
d = json.load(sys.stdin)
assert isinstance(d, (list, dict)), 'Unexpected type'
" "true"

    run_test "Jobs List" \
        "${CA_BASE}/v2/jobs" \
        "
import sys, json
d = json.load(sys.stdin)
assert isinstance(d, (list, dict)), 'Unexpected type'
" "true"

    run_test "System Cert - Signing" \
        "${CA_BASE}/v2/config/cert/signing" \
        "
import sys, json
d = json.load(sys.stdin)
assert len(d) > 0, 'Empty cert data'
" "true"

else
    skip_test "Account Login" "no auth configured"
    skip_test "Profile List" "no auth configured"
    skip_test "Get caUserCert Profile" "no auth configured"
    skip_test "Agent Cert Requests List" "no auth configured"
    skip_test "Audit Configuration" "no auth configured"
    skip_test "Admin Users List" "no auth configured"
    skip_test "Admin Groups List" "no auth configured"
    skip_test "Self Tests List" "no auth configured"
    skip_test "Authorities List" "no auth configured"
    skip_test "Config Features" "no auth configured"
    skip_test "Jobs List" "no auth configured"
    skip_test "System Cert - Signing" "no auth configured"
fi

echo ""

# ===========================================================
echo "--- Certificate Enrollment & Agent Approval ---"
echo ""
# ===========================================================

ENROLLED_REQ_ID=""

if [ -n "$ADMIN_PW" ]; then

    # Submit enrollment request via profileSubmit (public endpoint)
    CSR=$(openssl req -new -newkey rsa:2048 -nodes -keyout /dev/null \
        -subj '/CN=Test User/O=Test/C=US' 2>/dev/null | \
        grep -v '^-----' | tr -d '\n')

    ENROLL_RESPONSE=$(do_curl -X POST "${CA_BASE}/ee/ca/profileSubmit" \
        -d "profileId=caUserCert" \
        -d "renewal=false" \
        -d "xmlOutput=true" \
        -d "cert_request_type=pkcs10" \
        --data-urlencode "cert_request=${CSR}" \
        -d "sn_uid=testuser" \
        -d "sn_e=testuser@example.com" \
        -d "sn_cn=Test User" \
        2>/dev/null)

    TEST_NUM=$((TEST_NUM + 1))
    printf "  [%02d] %-50s " "$TEST_NUM" "Certificate Enrollment (profileSubmit)"

    # Status=0: success (auto-approved)
    # Status=2: deferred for agent approval (expected for caUserCert)
    # Status=1: invalid request (FAIL)
    if echo "$ENROLL_RESPONSE" | python3 -c "
import sys, re
data = sys.stdin.read()
# Check XML status
m = re.search(r'<Status>(\d+)</Status>', data)
if m:
    status = int(m.group(1))
    if status == 0 or status == 2:
        sys.exit(0)  # success or deferred (pending approval)
    else:
        sys.exit(1)
elif 'requestId' in data or 'pending' in data.lower():
    sys.exit(0)
else:
    sys.exit(1)
" 2>/dev/null; then
        echo "PASS (request deferred for approval)"
        PASS=$((PASS + 1))
        # Extract request ID from XML or JSON response
        ENROLLED_REQ_ID=$(echo "$ENROLL_RESPONSE" | python3 -c "
import sys, re
data = sys.stdin.read()
# Try XML RequestId
m = re.search(r'[Rr]equest[Ii][Dd][\"=>: ]*(\d+)', data)
if m:
    print(m.group(1))
" 2>/dev/null)
    else
        echo "FAIL"
        FAIL=$((FAIL + 1))
        echo "       Response: $(echo "$ENROLL_RESPONSE" | head -c 300)"
    fi

    # Agent approval
    if [ -n "$ENROLLED_REQ_ID" ]; then
        run_test "Agent Review Request #${ENROLLED_REQ_ID}" \
            "${CA_BASE}/v2/agent/certrequests/${ENROLLED_REQ_ID}" \
            "
import sys, json
d = json.load(sys.stdin)
assert len(d) > 0, 'No request data'
" "true"

        # Agent approve via POST
        TEST_NUM=$((TEST_NUM + 1))
        printf "  [%02d] %-50s " "$TEST_NUM" "Agent Approve Request #${ENROLLED_REQ_ID}"
        APPROVE_RESPONSE=$(do_curl --auth -X POST "${CA_BASE}/v2/agent/certrequests/${ENROLLED_REQ_ID}/approve" 2>/dev/null)
        APPROVE_CODE=$(do_curl --auth -X POST -o /dev/null -w '%{http_code}' "${CA_BASE}/v2/agent/certrequests/${ENROLLED_REQ_ID}/approve" 2>/dev/null)
        if [ "$APPROVE_CODE" = "200" ] || [ "$APPROVE_CODE" = "204" ]; then
            echo "PASS (HTTP $APPROVE_CODE)"
            PASS=$((PASS + 1))
        else
            echo "FAIL (HTTP $APPROVE_CODE)"
            echo "       Response: $(echo "$APPROVE_RESPONSE" | head -c 200)"
            FAIL=$((FAIL + 1))
        fi
    else
        skip_test "Agent Review Request" "no request ID from enrollment"
        skip_test "Agent Approve Request" "no request ID from enrollment"
    fi

else
    skip_test "Certificate Enrollment" "no auth configured"
    skip_test "Agent Review Request" "no auth configured"
    skip_test "Agent Approve Request" "no auth configured"
fi

echo ""

# ===========================================================
echo "--- KRA Public Endpoints ---"
echo ""
# ===========================================================

run_test "KRA Info" \
    "${KRA_BASE}/v2/info" \
    "
import sys, json
d = json.load(sys.stdin)
assert len(d) > 0, 'Empty KRA info'
"

run_test "KRA Transport Certificate" \
    "${KRA_BASE}/v2/config/cert/transport" \
    "
import sys, json
d = json.load(sys.stdin)
assert len(d) > 0, 'Empty cert data'
"

run_test "KRA Status (admin/kra/getStatus)" \
    "${KRA_BASE}/admin/kra/getStatus" \
    "
import sys
data = sys.stdin.read()
assert len(data) > 10, 'Empty status'
assert 'resource not found' not in data.lower(), '404 response'
"

echo ""

# ===========================================================
echo "--- KRA Authenticated Endpoints ---"
echo ""
# ===========================================================

if [ -n "$ADMIN_PW" ]; then

    run_test "KRA Account Login" \
        "${KRA_BASE}/v2/account/login" \
        "
import sys, json
d = json.load(sys.stdin)
assert len(d) > 0, 'Empty account data'
" "kra"

    run_test "KRA Key Requests List" \
        "${KRA_BASE}/v2/agent/keyrequests" \
        "
import sys, json
d = json.load(sys.stdin)
assert isinstance(d, (list, dict)), 'Unexpected type'
" "kra"

    run_test "KRA Keys List" \
        "${KRA_BASE}/v2/agent/keys" \
        "
import sys, json
d = json.load(sys.stdin)
assert isinstance(d, (list, dict)), 'Unexpected type'
" "kra"

    run_test "KRA Audit Configuration" \
        "${KRA_BASE}/v2/audit" \
        "
import sys, json
d = json.load(sys.stdin)
assert isinstance(d, dict), 'Expected object'
" "kra"

    run_test "KRA Admin Users List" \
        "${KRA_BASE}/v2/admin/users" \
        "
import sys, json
d = json.load(sys.stdin)
assert isinstance(d, (list, dict)), 'Unexpected type'
" "kra"

    run_test "KRA Admin Groups List" \
        "${KRA_BASE}/v2/admin/groups" \
        "
import sys, json
d = json.load(sys.stdin)
assert isinstance(d, (list, dict)), 'Unexpected type'
" "kra"

    run_test "KRA Self Tests List" \
        "${KRA_BASE}/v2/selftests" \
        "
import sys, json
d = json.load(sys.stdin)
assert isinstance(d, (list, dict)), 'Unexpected type'
" "kra"

    run_test "KRA Jobs List" \
        "${KRA_BASE}/v2/jobs" \
        "
import sys, json
d = json.load(sys.stdin)
assert isinstance(d, (list, dict)), 'Unexpected type'
" "kra"

else
    skip_test "KRA Account Login" "no auth configured"
    skip_test "KRA Key Requests List" "no auth configured"
    skip_test "KRA Keys List" "no auth configured"
    skip_test "KRA Audit Configuration" "no auth configured"
    skip_test "KRA Admin Users List" "no auth configured"
    skip_test "KRA Admin Groups List" "no auth configured"
    skip_test "KRA Self Tests List" "no auth configured"
    skip_test "KRA Jobs List" "no auth configured"
fi

echo ""

# ===========================================================
# Summary
# ===========================================================
TOTAL=$((PASS + FAIL + SKIP))
echo "============================================"
echo "Results: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped (${TOTAL} total)"
echo "============================================"

if [ "$FAIL" -gt 0 ]; then
    echo "OVERALL: FAIL"
    exit 1
elif [ "$PASS" -eq 0 ]; then
    echo "OVERALL: NO TESTS RAN"
    exit 2
else
    echo "OVERALL: PASS"
    exit 0
fi
