// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2024 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.server.ca.rest.v2;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.base.UnauthorizedException;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestRecord;
import com.netscape.cmscore.request.RequestRepository;
import com.netscape.cmsutil.ldap.LDAPUtil;

/**
 * User Dashboard REST API
 *
 * Provides endpoints for users to view their own certificates and requests.
 * All endpoints enforce user-based access control - users can only see
 * resources they own.
 *
 * Endpoints:
 *   GET /v2/dashboard/overview     - Summary statistics for current user
 *   GET /v2/dashboard/certificates - List user's certificates
 *   GET /v2/dashboard/requests     - List user's certificate requests
 *   GET /v2/dashboard/expiring     - List certificates expiring soon
 *   GET /v2/dashboard/activity     - Recent activity for user
 */
@WebServlet(name = "caDashboard", urlPatterns = "/v2/dashboard/*")
public class DashboardServlet extends CAServlet {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(DashboardServlet.class);

    private static final long serialVersionUID = 1L;

    // Expiration warning thresholds (in days)
    private static final int EXPIRING_SOON_DAYS = 30;
    private static final int EXPIRING_WARNING_DAYS = 90;

    /**
     * Get the current authenticated user ID from session context.
     * Throws UnauthorizedException if not authenticated.
     */
    private String getCurrentUserId() throws UnauthorizedException {
        SessionContext context = SessionContext.getContext();
        if (context == null) {
            throw new UnauthorizedException("Not authenticated");
        }

        String userId = (String) context.get(SessionContext.USER_ID);
        if (userId == null || userId.isEmpty()) {
            throw new UnauthorizedException("User ID not found in session");
        }

        return userId;
    }

    /**
     * Get the current user's email from session context.
     */
    private String getCurrentUserEmail() {
        SessionContext context = SessionContext.getContext();
        if (context == null) {
            return null;
        }

        AuthToken authToken = (AuthToken) context.get(SessionContext.AUTH_TOKEN);
        if (authToken != null) {
            return authToken.getInString(AuthToken.TOKEN_AUTHMGR_INST_NAME);
        }
        return null;
    }

    /**
     * GET /v2/dashboard/overview
     * Returns summary statistics for the current user.
     */
    @WebAction(method = HttpMethod.GET, paths = {"overview"})
    public void getOverview(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String userId = getCurrentUserId();
        logger.info("DashboardServlet: Getting overview for user: " + userId);

        CAEngine engine = getCAEngine();
        CertificateRepository certRepo = engine.getCertificateRepository();
        RequestRepository reqRepo = engine.getRequestRepository();

        DashboardOverview overview = new DashboardOverview();
        overview.setUserId(userId);

        // Count certificates by status
        int activeCerts = 0;
        int expiredCerts = 0;
        int revokedCerts = 0;
        int expiringSoonCerts = 0;

        Date now = new Date();
        Date soonDate = new Date(now.getTime() + (EXPIRING_SOON_DAYS * 24L * 60L * 60L * 1000L));

        // Get user's certificates (simplified - in production, use proper LDAP filter)
        // This would need a custom search filter based on requestor metadata
        List<CertRecord> userCerts = findUserCertificates(userId, certRepo);

        for (CertRecord cert : userCerts) {
            String status = cert.getStatus();
            if ("REVOKED".equals(status) || "REVOKED_EXPIRED".equals(status)) {
                revokedCerts++;
            } else if ("EXPIRED".equals(status)) {
                expiredCerts++;
            } else if ("VALID".equals(status)) {
                activeCerts++;
                // Check if expiring soon
                X509CertImpl x509 = cert.getCertificate();
                if (x509 != null && x509.getNotAfter().before(soonDate)) {
                    expiringSoonCerts++;
                }
            }
        }

        overview.setActiveCertificates(activeCerts);
        overview.setExpiredCertificates(expiredCerts);
        overview.setRevokedCertificates(revokedCerts);
        overview.setExpiringSoonCertificates(expiringSoonCerts);

        // Count pending requests
        int pendingRequests = countPendingRequests(userId, reqRepo);
        overview.setPendingRequests(pendingRequests);

        // Send response
        response.setContentType("application/json");
        PrintWriter out = response.getWriter();
        out.print(overview.toJson());
    }

    /**
     * GET /v2/dashboard/certificates
     * Returns list of certificates belonging to the current user.
     */
    @WebAction(method = HttpMethod.GET, paths = {"certificates"})
    public void getCertificates(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String userId = getCurrentUserId();
        logger.info("DashboardServlet: Getting certificates for user: " + userId);

        // Parse query parameters
        String status = request.getParameter("status"); // all, valid, expired, revoked
        String deviceType = request.getParameter("deviceType");
        int start = parseIntParam(request, "start", 0);
        int size = parseIntParam(request, "size", 20);

        CAEngine engine = getCAEngine();
        CertificateRepository certRepo = engine.getCertificateRepository();

        List<CertRecord> userCerts = findUserCertificates(userId, certRepo);

        // Filter and paginate
        List<DashboardCertificate> result = new ArrayList<>();
        int count = 0;

        for (CertRecord cert : userCerts) {
            // Apply filters
            if (status != null && !status.equals("all") && !status.equalsIgnoreCase(cert.getStatus())) {
                continue;
            }

            // Skip until start
            if (count < start) {
                count++;
                continue;
            }

            // Stop at size limit
            if (result.size() >= size) {
                break;
            }

            result.add(toDashboardCertificate(cert));
            count++;
        }

        // Send response
        response.setContentType("application/json");
        PrintWriter out = response.getWriter();
        out.print(toJsonArray(result));
    }

    /**
     * GET /v2/dashboard/requests
     * Returns list of certificate requests belonging to the current user.
     */
    @WebAction(method = HttpMethod.GET, paths = {"requests"})
    public void getRequests(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String userId = getCurrentUserId();
        logger.info("DashboardServlet: Getting requests for user: " + userId);

        String status = request.getParameter("status"); // all, pending, approved, rejected
        int start = parseIntParam(request, "start", 0);
        int size = parseIntParam(request, "size", 20);

        CAEngine engine = getCAEngine();
        RequestRepository reqRepo = engine.getRequestRepository();

        List<Request> userRequests = findUserRequests(userId, reqRepo);

        // Filter and paginate
        List<DashboardRequest> result = new ArrayList<>();
        int count = 0;

        for (Request req : userRequests) {
            // Apply status filter
            if (status != null && !status.equals("all")) {
                String reqStatus = req.getRequestStatus().toString();
                if (!status.equalsIgnoreCase(reqStatus)) {
                    continue;
                }
            }

            if (count < start) {
                count++;
                continue;
            }

            if (result.size() >= size) {
                break;
            }

            result.add(toDashboardRequest(req));
            count++;
        }

        response.setContentType("application/json");
        PrintWriter out = response.getWriter();
        out.print(toJsonArray(result));
    }

    /**
     * GET /v2/dashboard/expiring
     * Returns certificates expiring within the specified window.
     */
    @WebAction(method = HttpMethod.GET, paths = {"expiring"})
    public void getExpiring(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String userId = getCurrentUserId();
        int days = parseIntParam(request, "days", EXPIRING_WARNING_DAYS);

        logger.info("DashboardServlet: Getting expiring certs for user: " + userId + " within " + days + " days");

        CAEngine engine = getCAEngine();
        CertificateRepository certRepo = engine.getCertificateRepository();

        Date now = new Date();
        Date expirationWindow = new Date(now.getTime() + (days * 24L * 60L * 60L * 1000L));

        List<CertRecord> userCerts = findUserCertificates(userId, certRepo);
        List<DashboardCertificate> expiring = new ArrayList<>();

        for (CertRecord cert : userCerts) {
            if (!"VALID".equals(cert.getStatus())) {
                continue;
            }

            X509CertImpl x509 = cert.getCertificate();
            if (x509 != null && x509.getNotAfter().before(expirationWindow)) {
                DashboardCertificate dc = toDashboardCertificate(cert);
                dc.setDaysUntilExpiry(calculateDaysUntil(x509.getNotAfter()));
                expiring.add(dc);
            }
        }

        // Sort by expiration date (soonest first)
        expiring.sort((a, b) -> Integer.compare(a.getDaysUntilExpiry(), b.getDaysUntilExpiry()));

        response.setContentType("application/json");
        PrintWriter out = response.getWriter();
        out.print(toJsonArray(expiring));
    }

    /**
     * GET /v2/dashboard/activity
     * Returns recent activity for the current user.
     */
    @WebAction(method = HttpMethod.GET, paths = {"activity"})
    public void getActivity(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String userId = getCurrentUserId();
        int limit = parseIntParam(request, "limit", 10);

        logger.info("DashboardServlet: Getting activity for user: " + userId);

        CAEngine engine = getCAEngine();
        CertificateRepository certRepo = engine.getCertificateRepository();
        RequestRepository reqRepo = engine.getRequestRepository();

        List<DashboardActivity> activities = new ArrayList<>();

        // Build activity from user's certificates
        List<CertRecord> certs = findUserCertificates(userId, certRepo);
        for (CertRecord cert : certs) {
            DashboardActivity activity = new DashboardActivity();
            activity.setResourceType("certificate");
            activity.setResourceId(cert.getSerialNumber().toString());

            String status = cert.getStatus();
            if ("REVOKED".equals(status) || "REVOKED_EXPIRED".equals(status)) {
                activity.setAction("REVOKED");
                activity.setDetails("Certificate revoked");
                activity.setTimestamp(cert.getRevokedOn());
            } else if ("EXPIRED".equals(status)) {
                activity.setAction("EXPIRED");
                activity.setDetails("Certificate expired");
                X509CertImpl x509 = cert.getCertificate();
                activity.setTimestamp(x509 != null ? x509.getNotAfter() : cert.getCreateTime());
            } else {
                activity.setAction("ISSUED");
                activity.setDetails("Certificate issued");
                activity.setTimestamp(cert.getCreateTime());
            }

            if (activity.getTimestamp() == null) {
                activity.setTimestamp(cert.getCreateTime());
            }

            activities.add(activity);
        }

        // Build activity from user's requests
        List<Request> requests = findUserRequests(userId, reqRepo);
        for (Request req : requests) {
            DashboardActivity activity = new DashboardActivity();
            activity.setResourceType("request");
            activity.setResourceId(req.getRequestId().toString());
            activity.setAction(req.getRequestStatus().toString());
            activity.setDetails(req.getRequestType() + " request");
            activity.setTimestamp(req.getModificationTime() != null
                    ? req.getModificationTime() : req.getCreationTime());
            activities.add(activity);
        }

        // Sort by timestamp descending (most recent first)
        activities.sort(Comparator.comparing(
                DashboardActivity::getTimestamp, Comparator.nullsLast(Comparator.reverseOrder())));

        // Limit results
        if (activities.size() > limit) {
            activities = activities.subList(0, limit);
        }

        response.setContentType("application/json");
        PrintWriter out = response.getWriter();
        out.print(toJsonArray(activities));
    }

    // Helper methods

    private List<CertRecord> findUserCertificates(String userId, CertificateRepository certRepo) {
        List<CertRecord> results = new ArrayList<>();
        try {
            String filter = "(" + CertRecord.ATTR_ISSUED_BY + "=" + LDAPUtil.escapeFilter(userId) + ")";
            int timeLimit = 10; // seconds
            int start = 0;
            int size = 100;

            Iterator<CertRecord> it = certRepo.searchCertificates(filter, timeLimit, start, size);
            while (it != null && it.hasNext()) {
                CertRecord rec = it.next();
                if (rec != null) {
                    results.add(rec);
                }
            }
        } catch (Exception e) {
            logger.warn("DashboardServlet: Error finding certificates for user " + userId + ": " + e.getMessage(), e);
        }
        return results;
    }

    private List<Request> findUserRequests(String userId, RequestRepository reqRepo) {
        List<Request> results = new ArrayList<>();
        try {
            String filter = "(requestState=*)";
            int timeLimit = 10; // seconds
            int start = 0;
            int maxScan = 500;

            Iterator<RequestRecord> it = reqRepo.searchRequest(filter, timeLimit, start, maxScan);
            while (it != null && it.hasNext() && results.size() < 100) {
                RequestRecord record = it.next();
                if (record == null) continue;

                Request req = record.toRequest();
                String reqUid = req.getExtDataInString(Request.AUTH_TOKEN, "uid");
                if (userId.equals(reqUid)) {
                    results.add(req);
                }
            }
        } catch (Exception e) {
            logger.warn("DashboardServlet: Error finding requests for user " + userId + ": " + e.getMessage(), e);
        }
        return results;
    }

    private int countPendingRequests(String userId, RequestRepository reqRepo) {
        int count = 0;
        try {
            String filter = "(requestState=pending)";
            int timeLimit = 10; // seconds
            int start = 0;
            int maxScan = 500;

            Iterator<RequestRecord> it = reqRepo.searchRequest(filter, timeLimit, start, maxScan);
            while (it != null && it.hasNext()) {
                RequestRecord record = it.next();
                if (record == null) continue;

                Request req = record.toRequest();
                String reqUid = req.getExtDataInString(Request.AUTH_TOKEN, "uid");
                if (userId.equals(reqUid)) {
                    count++;
                }
            }
        } catch (Exception e) {
            logger.warn("DashboardServlet: Error counting pending requests for user " + userId + ": " + e.getMessage(), e);
        }
        return count;
    }

    private DashboardCertificate toDashboardCertificate(CertRecord cert) {
        DashboardCertificate dc = new DashboardCertificate();
        dc.setSerialNumber(cert.getSerialNumber().toString());
        dc.setSerialNumberHex("0x" + cert.getSerialNumber().toString(16).toUpperCase());
        dc.setStatus(cert.getStatus());

        X509CertImpl x509 = cert.getCertificate();
        if (x509 != null) {
            dc.setSubjectDN(x509.getSubjectName().toString());
            dc.setIssuerDN(x509.getIssuerName().toString());
            dc.setNotBefore(x509.getNotBefore());
            dc.setNotAfter(x509.getNotAfter());
            dc.setDaysUntilExpiry(calculateDaysUntil(x509.getNotAfter()));
        }

        // Get device metadata from cert record
        if (cert.getMetaInfo() != null) {
            try {
                dc.setDeviceType((String) cert.getMetaInfo().get("deviceType"));
                dc.setDeviceId((String) cert.getMetaInfo().get("deviceId"));
                dc.setDeviceGroup((String) cert.getMetaInfo().get("deviceGroup"));
            } catch (Exception e) {
                // Ignore metadata errors
            }
        }

        return dc;
    }

    private DashboardRequest toDashboardRequest(Request req) {
        DashboardRequest dr = new DashboardRequest();
        dr.setRequestId(req.getRequestId().toString());
        dr.setRequestType(req.getRequestType());
        dr.setStatus(req.getRequestStatus().toString());
        dr.setCreatedOn(req.getCreationTime());
        dr.setModifiedOn(req.getModificationTime());
        dr.setProfileId(req.getExtDataInString(Request.PROFILE_ID));
        return dr;
    }

    private int calculateDaysUntil(Date date) {
        if (date == null) {
            return -1;
        }
        long diff = date.getTime() - System.currentTimeMillis();
        return (int) (diff / (24L * 60L * 60L * 1000L));
    }

    private int parseIntParam(HttpServletRequest request, String name, int defaultValue) {
        String value = request.getParameter(name);
        if (value != null) {
            try {
                return Integer.parseInt(value);
            } catch (NumberFormatException e) {
                // Use default
            }
        }
        return defaultValue;
    }

    private String toJsonArray(List<?> list) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < list.size(); i++) {
            if (i > 0) sb.append(",");
            Object item = list.get(i);
            if (item instanceof JsonSerializable) {
                sb.append(((JsonSerializable) item).toJson());
            }
        }
        sb.append("]");
        return sb.toString();
    }

    // Inner classes for response objects

    interface JsonSerializable {
        String toJson();
    }

    public static class DashboardOverview implements JsonSerializable {
        private String userId;
        private int activeCertificates;
        private int expiredCertificates;
        private int revokedCertificates;
        private int expiringSoonCertificates;
        private int pendingRequests;

        public void setUserId(String userId) { this.userId = userId; }
        public void setActiveCertificates(int n) { this.activeCertificates = n; }
        public void setExpiredCertificates(int n) { this.expiredCertificates = n; }
        public void setRevokedCertificates(int n) { this.revokedCertificates = n; }
        public void setExpiringSoonCertificates(int n) { this.expiringSoonCertificates = n; }
        public void setPendingRequests(int n) { this.pendingRequests = n; }

        @Override
        public String toJson() {
            return String.format(
                "{\"userId\":\"%s\",\"activeCertificates\":%d,\"expiredCertificates\":%d," +
                "\"revokedCertificates\":%d,\"expiringSoonCertificates\":%d,\"pendingRequests\":%d}",
                userId, activeCertificates, expiredCertificates,
                revokedCertificates, expiringSoonCertificates, pendingRequests);
        }
    }

    public static class DashboardCertificate implements JsonSerializable {
        private String serialNumber;
        private String serialNumberHex;
        private String subjectDN;
        private String issuerDN;
        private String status;
        private Date notBefore;
        private Date notAfter;
        private int daysUntilExpiry;
        private String deviceType;
        private String deviceId;
        private String deviceGroup;

        public void setSerialNumber(String s) { this.serialNumber = s; }
        public void setSerialNumberHex(String s) { this.serialNumberHex = s; }
        public void setSubjectDN(String s) { this.subjectDN = s; }
        public void setIssuerDN(String s) { this.issuerDN = s; }
        public void setStatus(String s) { this.status = s; }
        public void setNotBefore(Date d) { this.notBefore = d; }
        public void setNotAfter(Date d) { this.notAfter = d; }
        public void setDaysUntilExpiry(int d) { this.daysUntilExpiry = d; }
        public int getDaysUntilExpiry() { return daysUntilExpiry; }
        public void setDeviceType(String s) { this.deviceType = s; }
        public void setDeviceId(String s) { this.deviceId = s; }
        public void setDeviceGroup(String s) { this.deviceGroup = s; }

        @Override
        public String toJson() {
            return String.format(
                "{\"serialNumber\":\"%s\",\"serialNumberHex\":\"%s\",\"subjectDN\":\"%s\"," +
                "\"issuerDN\":\"%s\",\"status\":\"%s\",\"daysUntilExpiry\":%d," +
                "\"deviceType\":\"%s\",\"deviceId\":\"%s\",\"deviceGroup\":\"%s\"}",
                serialNumber, serialNumberHex, escapeJson(subjectDN),
                escapeJson(issuerDN), status, daysUntilExpiry,
                deviceType != null ? deviceType : "",
                deviceId != null ? deviceId : "",
                deviceGroup != null ? deviceGroup : "");
        }

        private String escapeJson(String s) {
            if (s == null) return "";
            return s.replace("\\", "\\\\").replace("\"", "\\\"");
        }
    }

    public static class DashboardRequest implements JsonSerializable {
        private String requestId;
        private String requestType;
        private String status;
        private Date createdOn;
        private Date modifiedOn;
        private String profileId;

        public void setRequestId(String s) { this.requestId = s; }
        public void setRequestType(String s) { this.requestType = s; }
        public void setStatus(String s) { this.status = s; }
        public void setCreatedOn(Date d) { this.createdOn = d; }
        public void setModifiedOn(Date d) { this.modifiedOn = d; }
        public void setProfileId(String s) { this.profileId = s; }

        @Override
        public String toJson() {
            return String.format(
                "{\"requestId\":\"%s\",\"requestType\":\"%s\",\"status\":\"%s\",\"profileId\":\"%s\"}",
                requestId, requestType, status, profileId != null ? profileId : "");
        }
    }

    public static class DashboardActivity implements JsonSerializable {
        private String action;
        private String resourceType;
        private String resourceId;
        private Date timestamp;
        private String details;

        public void setAction(String action) { this.action = action; }
        public void setResourceType(String resourceType) { this.resourceType = resourceType; }
        public void setResourceId(String resourceId) { this.resourceId = resourceId; }
        public void setTimestamp(Date timestamp) { this.timestamp = timestamp; }
        public Date getTimestamp() { return timestamp; }
        public void setDetails(String details) { this.details = details; }

        @Override
        public String toJson() {
            return String.format(
                "{\"action\":\"%s\",\"resourceType\":\"%s\",\"resourceId\":\"%s\",\"details\":\"%s\"}",
                action != null ? action : "",
                resourceType != null ? resourceType : "",
                resourceId != null ? resourceId : "",
                details != null ? details : "");
        }
    }
}
