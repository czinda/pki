//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import jakarta.inject.Inject;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.UnauthorizedException;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestRecord;
import com.netscape.cmscore.request.RequestRepository;
import com.netscape.cmsutil.ldap.LDAPUtil;

/**
 * User Dashboard REST API (JAX-RS resource for Quarkus).
 * Replaces DashboardServlet.
 *
 * Provides endpoints for users to view their own certificates and requests.
 * All endpoints enforce user-based access control - users can only see
 * resources they own.
 */
@Path("v2/dashboard")
public class CADashboardResource {

    private static final Logger logger = LoggerFactory.getLogger(CADashboardResource.class);

    private static final int EXPIRING_SOON_DAYS = 30;
    private static final int EXPIRING_WARNING_DAYS = 90;

    @Inject
    CAEngineQuarkus engineQuarkus;

    @Context
    SecurityContext securityContext;

    private String getCurrentUserId() throws UnauthorizedException {
        if (securityContext.getUserPrincipal() == null) {
            throw new UnauthorizedException("Not authenticated");
        }
        String userId = securityContext.getUserPrincipal().getName();
        if (userId == null || userId.isEmpty()) {
            throw new UnauthorizedException("User ID not found in session");
        }
        return userId;
    }

    @GET
    @Path("overview")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getOverview() throws Exception {
        String userId = getCurrentUserId();
        logger.info("CADashboardResource: Getting overview for user: {}", userId);

        CAEngine engine = engineQuarkus.getEngine();
        CertificateRepository certRepo = engine.getCertificateRepository();
        RequestRepository reqRepo = engine.getRequestRepository();

        int activeCerts = 0;
        int expiredCerts = 0;
        int revokedCerts = 0;
        int expiringSoonCerts = 0;

        Date now = new Date();
        Date soonDate = new Date(now.getTime() + (EXPIRING_SOON_DAYS * 24L * 60L * 60L * 1000L));

        List<CertRecord> userCerts = findUserCertificates(userId, certRepo);

        for (CertRecord cert : userCerts) {
            String status = cert.getStatus();
            if ("REVOKED".equals(status) || "REVOKED_EXPIRED".equals(status)) {
                revokedCerts++;
            } else if ("EXPIRED".equals(status)) {
                expiredCerts++;
            } else if ("VALID".equals(status)) {
                activeCerts++;
                X509CertImpl x509 = cert.getCertificate();
                if (x509 != null && x509.getNotAfter().before(soonDate)) {
                    expiringSoonCerts++;
                }
            }
        }

        int pendingRequests = countPendingRequests(userId, reqRepo);

        String json = String.format(
                "{\"userId\":\"%s\",\"activeCertificates\":%d,\"expiredCertificates\":%d," +
                "\"revokedCertificates\":%d,\"expiringSoonCertificates\":%d,\"pendingRequests\":%d}",
                userId, activeCerts, expiredCerts,
                revokedCerts, expiringSoonCerts, pendingRequests);

        return Response.ok(json).build();
    }

    @GET
    @Path("certificates")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getCertificates(
            @QueryParam("status") String status,
            @QueryParam("start") @DefaultValue("0") int start,
            @QueryParam("size") @DefaultValue("20") int size) throws Exception {

        String userId = getCurrentUserId();
        logger.info("CADashboardResource: Getting certificates for user: {}", userId);

        CAEngine engine = engineQuarkus.getEngine();
        CertificateRepository certRepo = engine.getCertificateRepository();

        List<CertRecord> userCerts = findUserCertificates(userId, certRepo);

        List<String> result = new ArrayList<>();
        int count = 0;

        for (CertRecord cert : userCerts) {
            if (status != null && !status.equals("all") && !status.equalsIgnoreCase(cert.getStatus())) {
                continue;
            }

            if (count < start) {
                count++;
                continue;
            }

            if (result.size() >= size) {
                break;
            }

            result.add(toCertificateJson(cert));
            count++;
        }

        return Response.ok(toJsonArray(result)).build();
    }

    @GET
    @Path("requests")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getRequests(
            @QueryParam("status") String status,
            @QueryParam("start") @DefaultValue("0") int start,
            @QueryParam("size") @DefaultValue("20") int size) throws Exception {

        String userId = getCurrentUserId();
        logger.info("CADashboardResource: Getting requests for user: {}", userId);

        CAEngine engine = engineQuarkus.getEngine();
        RequestRepository reqRepo = engine.getRequestRepository();

        List<Request> userRequests = findUserRequests(userId, reqRepo);

        List<String> result = new ArrayList<>();
        int count = 0;

        for (Request req : userRequests) {
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

            result.add(toRequestJson(req));
            count++;
        }

        return Response.ok(toJsonArray(result)).build();
    }

    @GET
    @Path("expiring")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getExpiring(
            @QueryParam("days") @DefaultValue("90") int days) throws Exception {

        String userId = getCurrentUserId();
        logger.info("CADashboardResource: Getting expiring certs for user: {} within {} days", userId, days);

        CAEngine engine = engineQuarkus.getEngine();
        CertificateRepository certRepo = engine.getCertificateRepository();

        Date now = new Date();
        Date expirationWindow = new Date(now.getTime() + (days * 24L * 60L * 60L * 1000L));

        List<CertRecord> userCerts = findUserCertificates(userId, certRepo);

        // Collect expiring certs with days-until-expiry for sorting
        List<Object[]> expiring = new ArrayList<>();

        for (CertRecord cert : userCerts) {
            if (!"VALID".equals(cert.getStatus())) {
                continue;
            }

            X509CertImpl x509 = cert.getCertificate();
            if (x509 != null && x509.getNotAfter().before(expirationWindow)) {
                int daysUntil = calculateDaysUntil(x509.getNotAfter());
                expiring.add(new Object[]{cert, daysUntil});
            }
        }

        expiring.sort(Comparator.comparingInt(a -> (int) a[1]));

        List<String> result = new ArrayList<>();
        for (Object[] entry : expiring) {
            result.add(toCertificateJson((CertRecord) entry[0]));
        }

        return Response.ok(toJsonArray(result)).build();
    }

    @GET
    @Path("activity")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getActivity(
            @QueryParam("limit") @DefaultValue("10") int limit) throws Exception {

        String userId = getCurrentUserId();
        logger.info("CADashboardResource: Getting activity for user: {}", userId);

        CAEngine engine = engineQuarkus.getEngine();
        CertificateRepository certRepo = engine.getCertificateRepository();
        RequestRepository reqRepo = engine.getRequestRepository();

        List<Object[]> activities = new ArrayList<>(); // [json, timestamp]

        List<CertRecord> certs = findUserCertificates(userId, certRepo);
        for (CertRecord cert : certs) {
            String action;
            String details;
            Date timestamp;

            String status = cert.getStatus();
            if ("REVOKED".equals(status) || "REVOKED_EXPIRED".equals(status)) {
                action = "REVOKED";
                details = "Certificate revoked";
                timestamp = cert.getRevokedOn();
            } else if ("EXPIRED".equals(status)) {
                action = "EXPIRED";
                details = "Certificate expired";
                X509CertImpl x509 = cert.getCertificate();
                timestamp = x509 != null ? x509.getNotAfter() : cert.getCreateTime();
            } else {
                action = "ISSUED";
                details = "Certificate issued";
                timestamp = cert.getCreateTime();
            }

            if (timestamp == null) {
                timestamp = cert.getCreateTime();
            }

            String json = String.format(
                    "{\"action\":\"%s\",\"resourceType\":\"certificate\",\"resourceId\":\"%s\",\"details\":\"%s\"}",
                    action, cert.getSerialNumber().toString(), details);
            activities.add(new Object[]{json, timestamp});
        }

        List<Request> requests = findUserRequests(userId, reqRepo);
        for (Request req : requests) {
            Date timestamp = req.getModificationTime() != null
                    ? req.getModificationTime() : req.getCreationTime();

            String json = String.format(
                    "{\"action\":\"%s\",\"resourceType\":\"request\",\"resourceId\":\"%s\",\"details\":\"%s request\"}",
                    req.getRequestStatus().toString(),
                    req.getRequestId().toString(),
                    req.getRequestType());
            activities.add(new Object[]{json, timestamp});
        }

        activities.sort((a, b) -> {
            Date da = (Date) a[1];
            Date db = (Date) b[1];
            if (da == null && db == null) return 0;
            if (da == null) return 1;
            if (db == null) return -1;
            return db.compareTo(da);
        });

        List<String> result = new ArrayList<>();
        for (int i = 0; i < Math.min(limit, activities.size()); i++) {
            result.add((String) activities.get(i)[0]);
        }

        return Response.ok(toJsonArray(result)).build();
    }

    // Helper methods

    private List<CertRecord> findUserCertificates(String userId, CertificateRepository certRepo) {
        List<CertRecord> results = new ArrayList<>();
        try {
            String filter = "(" + CertRecord.ATTR_ISSUED_BY + "=" + LDAPUtil.escapeFilter(userId) + ")";
            int timeLimit = 10;
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
            logger.warn("CADashboardResource: Error finding certificates for user {}: {}", userId, e.getMessage(), e);
        }
        return results;
    }

    private List<Request> findUserRequests(String userId, RequestRepository reqRepo) {
        List<Request> results = new ArrayList<>();
        try {
            String filter = "(requestState=*)";
            int timeLimit = 10;
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
            logger.warn("CADashboardResource: Error finding requests for user {}: {}", userId, e.getMessage(), e);
        }
        return results;
    }

    private int countPendingRequests(String userId, RequestRepository reqRepo) {
        int count = 0;
        try {
            String filter = "(requestState=pending)";
            int timeLimit = 10;
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
            logger.warn("CADashboardResource: Error counting pending requests for user {}: {}", userId, e.getMessage(), e);
        }
        return count;
    }

    private String toCertificateJson(CertRecord cert) {
        X509CertImpl x509 = cert.getCertificate();
        String subjectDN = "";
        String issuerDN = "";
        int daysUntilExpiry = -1;

        if (x509 != null) {
            subjectDN = escapeJson(x509.getSubjectName().toString());
            issuerDN = escapeJson(x509.getIssuerName().toString());
            daysUntilExpiry = calculateDaysUntil(x509.getNotAfter());
        }

        return String.format(
                "{\"serialNumber\":\"%s\",\"serialNumberHex\":\"0x%s\",\"subjectDN\":\"%s\"," +
                "\"issuerDN\":\"%s\",\"status\":\"%s\",\"daysUntilExpiry\":%d}",
                cert.getSerialNumber().toString(),
                cert.getSerialNumber().toString(16).toUpperCase(),
                subjectDN, issuerDN, cert.getStatus(), daysUntilExpiry);
    }

    private String toRequestJson(Request req) {
        String profileId = req.getExtDataInString(Request.PROFILE_ID);
        return String.format(
                "{\"requestId\":\"%s\",\"requestType\":\"%s\",\"status\":\"%s\",\"profileId\":\"%s\"}",
                req.getRequestId().toString(),
                req.getRequestType(),
                req.getRequestStatus().toString(),
                profileId != null ? profileId : "");
    }

    private int calculateDaysUntil(Date date) {
        if (date == null) {
            return -1;
        }
        long diff = date.getTime() - System.currentTimeMillis();
        return (int) (diff / (24L * 60L * 60L * 1000L));
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private String toJsonArray(List<String> items) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append(items.get(i));
        }
        sb.append("]");
        return sb.toString();
    }
}
