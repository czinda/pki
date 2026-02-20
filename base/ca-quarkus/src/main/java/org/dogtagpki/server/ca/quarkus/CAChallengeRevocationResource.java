//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.math.BigInteger;
import java.util.Date;
import java.util.Vector;

import jakarta.inject.Inject;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.x509.CRLExtensions;
import org.mozilla.jss.netscape.security.x509.CRLReasonExtension;
import org.mozilla.jss.netscape.security.x509.InvalidityDateExtension;
import org.mozilla.jss.netscape.security.x509.RevocationReason;
import org.mozilla.jss.netscape.security.x509.RevokedCertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.ca.CRLIssuingPoint;
import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.dbs.RecordPagedList;
import com.netscape.cmscore.request.CertRequestRepository;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestQueue;

/**
 * JAX-RS resource replacing the legacy ChallengeRevocationServlet1 CMSServlet.
 * Handles challenge-based certificate revocation by serial number.
 * Legacy URL: /ee/ca/challengeRevoke1
 */
@Path("ee/ca/challengeRevoke1")
public class CAChallengeRevocationResource {

    private static final Logger logger = LoggerFactory.getLogger(CAChallengeRevocationResource.class);

    @Inject
    CAEngineQuarkus engineQuarkus;

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response challengeRevoke(
            @FormParam("certSerialToRevoke") String serialNoStr,
            @FormParam("reasonCode") String reasonCodeStr,
            @FormParam("requestorComments") String comments) {

        logger.info("CAChallengeRevocationResource: Processing challenge revocation");

        CAEngine engine = engineQuarkus.getEngine();
        CertificateRepository cr = engine.getCertificateRepository();

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode result = mapper.createObjectNode();

        if (serialNoStr == null || serialNoStr.isEmpty()) {
            result.put("Status", "1");
            result.put("Error", "Missing certificate serial number");
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(result.toString())
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        int reasonCode = 0;
        if (reasonCodeStr != null) {
            try {
                reasonCode = Integer.parseInt(reasonCodeStr);
            } catch (NumberFormatException e) {
                // use default
            }
        }

        try {
            BigInteger serialNo;
            serialNoStr = serialNoStr.trim();
            if (serialNoStr.startsWith("0x") || serialNoStr.startsWith("0X")) {
                serialNo = new BigInteger(serialNoStr.substring(2), 16);
            } else {
                serialNo = new BigInteger(serialNoStr);
            }

            // Build filter to find the cert
            String revokeAll = "(|(certRecordId=" + serialNo.toString() + "))";

            // Construct CRL extensions
            RevocationReason revReason = RevocationReason.valueOf(reasonCode);
            CRLReasonExtension crlReasonExtn = new CRLReasonExtension(revReason);
            CRLExtensions entryExtn = new CRLExtensions();
            entryExtn.set(crlReasonExtn.getName(), crlReasonExtn);

            Vector<X509CertImpl> oldCertsV = new Vector<>();
            Vector<RevokedCertImpl> revCertImplsV = new Vector<>();
            ArrayNode certsArray = mapper.createArrayNode();
            int count = 0;

            RecordPagedList<CertRecord> list = cr.findPagedCertRecords(revokeAll, null, null);

            for (CertRecord rec : list) {
                X509CertImpl cert = rec.getCertificate();
                ObjectNode certNode = mapper.createObjectNode();
                certNode.put("serialNumber", cert.getSerialNumber().toString(16));

                if (rec.getStatus().equals(CertRecord.STATUS_REVOKED)) {
                    certNode.put("error", "Certificate " +
                            cert.getSerialNumber().toString() +
                            " is already revoked.");
                } else {
                    oldCertsV.addElement(cert);
                    RevokedCertImpl revCertImpl = new RevokedCertImpl(
                            cert.getSerialNumber(), new Date(), entryExtn);
                    revCertImplsV.addElement(revCertImpl);
                    count++;
                    certNode.putNull("error");
                }
                certsArray.add(certNode);
            }

            if (count == 0) {
                result.put("Status", "1");
                result.put("Error", "No matched certificate is found");
                result.put("totalRecordCount", 0);
                return Response.status(Response.Status.NOT_FOUND)
                        .entity(result.toString())
                        .type(MediaType.APPLICATION_JSON)
                        .build();
            }

            // Create and submit revocation request
            X509CertImpl[] oldCerts = oldCertsV.toArray(new X509CertImpl[0]);
            RevokedCertImpl[] revCertImpls = revCertImplsV.toArray(new RevokedCertImpl[0]);

            CertRequestRepository requestRepository = engine.getCertRequestRepository();
            Request revReq = requestRepository.createRequest(Request.REVOCATION_REQUEST);

            revReq.setExtData(Request.CERT_INFO, revCertImpls);
            revReq.setExtData(Request.REQ_TYPE, Request.REVOCATION_REQUEST);
            revReq.setExtData(Request.REQUESTOR_TYPE, Request.REQUESTOR_AGENT);
            revReq.setExtData(Request.OLD_CERTS, oldCerts);
            if (comments != null) {
                revReq.setExtData(Request.REQUESTOR_COMMENTS, comments);
            }

            RequestQueue mQueue = engine.getRequestQueue();
            mQueue.processRequest(revReq);
            RequestStatus stat = revReq.getRequestStatus();

            result.put("totalRecordCount", count);
            result.set("certs", certsArray);

            if (stat == RequestStatus.COMPLETE) {
                Integer reqResult = revReq.getExtDataInInteger(Request.RESULT);

                if (reqResult != null && reqResult.equals(Request.RES_ERROR)) {
                    String[] svcErrors = revReq.getExtDataInStringArray(Request.SVCERRORS);
                    StringBuilder errorStr = new StringBuilder();
                    if (svcErrors != null) {
                        for (String err : svcErrors) {
                            if (err != null) errorStr.append(err);
                        }
                    }
                    result.put("Status", "1");
                    result.put("Error", errorStr.toString());
                    result.put("revoked", "no");
                } else {
                    result.put("Status", "0");
                    result.put("revoked", "yes");

                    // CRL update status
                    Integer updateCRLResult = revReq.getExtDataInInteger(Request.CRL_UPDATE_STATUS);
                    if (updateCRLResult != null) {
                        result.put("updateCRL", "yes");
                        result.put("updateCRLSuccess",
                                updateCRLResult.equals(Request.RES_SUCCESS) ? "yes" : "no");
                    }
                }

            } else if (stat == RequestStatus.PENDING) {
                result.put("Status", "0");
                result.put("revoked", "pending");
                result.put("Error", "Request Pending");

            } else {
                Vector<String> errors = revReq.getExtDataInStringVector(Request.ERRORS);
                StringBuilder errorStr = new StringBuilder();
                if (errors != null) {
                    for (String err : errors) {
                        errorStr.append(err);
                    }
                }
                result.put("Status", "1");
                result.put("revoked", "no");
                result.put("Error", errorStr.toString());
            }

        } catch (Exception e) {
            logger.error("CAChallengeRevocationResource: Error: {}", e.getMessage(), e);
            result.put("Status", "1");
            result.put("Error", e.getMessage());
            return Response.serverError()
                    .entity(result.toString())
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        return Response.ok(result.toString(), MediaType.APPLICATION_JSON).build();
    }
}
