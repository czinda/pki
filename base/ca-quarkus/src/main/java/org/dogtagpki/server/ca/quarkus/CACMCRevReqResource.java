//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;
import java.util.Locale;
import java.util.Vector;

import jakarta.inject.Inject;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.x509.RevocationReason;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.servlet.cert.RevocationProcessor;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.dbs.RecordPagedList;
import com.netscape.cmscore.request.Request;

/**
 * JAX-RS resource replacing the legacy CMCRevReqServlet.
 * Handles CMC-format (Certificate Management over CMS) revocation requests.
 * Processes revocation requests that include a CMC-encoded request body
 * containing the serial numbers of certificates to revoke and the
 * revocation reason.
 * Legacy URL: /ee/ca/CMCRevReq
 */
@Path("ee/ca/cmcRevReq")
public class CACMCRevReqResource {

    private static final Logger logger = LoggerFactory.getLogger(CACMCRevReqResource.class);

    private static final String REVOKE = "revoke";
    private static final String ON_HOLD = "on-hold";
    private static final int ON_HOLD_REASON = 6;

    @Inject
    CAEngineQuarkus engineQuarkus;

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response cmcRevReq(
            @FormParam("cmcRequest") String cmcRequest,
            @FormParam("certSerialToRevoke") String serialNumbersStr,
            @FormParam("reasonCode") String reasonCodeStr,
            @FormParam("comments") String comments,
            @FormParam("requestId") String requestId) {

        logger.info("CACMCRevReqResource: Processing CMC revocation request");

        CAEngine engine = engineQuarkus.getEngine();
        CertificateRepository certDB = engine.getCertificateRepository();

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode result = mapper.createObjectNode();

        if (cmcRequest == null || cmcRequest.isEmpty()) {
            result.put("Status", "1");
            result.put("Error", "Missing cmcRequest parameter");
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(result.toString())
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        // Parse reason code (default to 0 = unspecified)
        int reasonCode = 0;
        if (reasonCodeStr != null && !reasonCodeStr.isEmpty()) {
            try {
                reasonCode = Integer.parseInt(reasonCodeStr);
            } catch (NumberFormatException e) {
                result.put("Status", "1");
                result.put("Error", "Invalid reason code: " + reasonCodeStr);
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(result.toString())
                        .type(MediaType.APPLICATION_JSON)
                        .build();
            }
        }

        // Parse serial numbers
        BigInteger[] serialNoArray = null;
        if (serialNumbersStr != null && !serialNumbersStr.isEmpty()) {
            try {
                String[] parts = serialNumbersStr.split("[,\\s]+");
                serialNoArray = new BigInteger[parts.length];
                for (int i = 0; i < parts.length; i++) {
                    String s = parts[i].trim();
                    if (s.startsWith("0x") || s.startsWith("0X")) {
                        serialNoArray[i] = new BigInteger(s.substring(2), 16);
                    } else {
                        serialNoArray[i] = new BigInteger(s);
                    }
                }
            } catch (NumberFormatException e) {
                result.put("Status", "1");
                result.put("Error", "Invalid serial number format");
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(result.toString())
                        .type(MediaType.APPLICATION_JSON)
                        .build();
            }
        }

        if (serialNoArray == null || serialNoArray.length == 0) {
            result.put("Status", "1");
            result.put("Error", "No matched certificate is found");
            return Response.status(Response.Status.NOT_FOUND)
                    .entity(result.toString())
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        RevocationReason revReason = RevocationReason.valueOf(reasonCode);

        RevocationProcessor processor = new RevocationProcessor("CACMCRevReqResource", Locale.getDefault());
        processor.setCMSEngine(engine);

        result.put("totalRecordCount", serialNoArray.length);
        result.put("verifiedRecordCount", serialNoArray.length);
        result.put("reasonCode", reasonCode);
        if (revReason != null) {
            result.put("reason", revReason.toString());
        }

        ArrayNode certsArray = mapper.createArrayNode();

        try {
            processor.init();

            processor.setSerialNumber(new CertId(serialNoArray[0]));
            processor.setRevocationReason(revReason);

            // Determine if this is a revoke or unrevoke (remove from CRL)
            if (revReason != null && revReason == RevocationReason.REMOVE_FROM_CRL) {
                processor.setRequestType(RevocationProcessor.OFF_HOLD);
            } else if (reasonCode == ON_HOLD_REASON) {
                processor.setRequestType(RevocationProcessor.ON_HOLD);
            } else {
                processor.setRequestType(RevocationProcessor.REVOKE);
            }

            processor.setComments(comments);
            processor.setAuthority(engine.getCA());
            // Look up and validate each certificate
            X509CertImpl[] certs = new X509CertImpl[serialNoArray.length];
            for (int i = 0; i < serialNoArray.length; i++) {
                certs[i] = certDB.getX509Certificate(serialNoArray[i]);

                ObjectNode certNode = mapper.createObjectNode();
                certNode.put("serialNumber", serialNoArray[i].toString(16));
                if (certs[i] != null) {
                    certNode.put("subject", certs[i].getSubjectName().toString());
                    certNode.put("validNotBefore", certs[i].getNotBefore().getTime());
                    certNode.put("validNotAfter", certs[i].getNotAfter().getTime());
                }
                certsArray.add(certNode);
            }

            // Build the filter for finding cert records
            String revokeAll = "(|(certRecordId=" + serialNoArray[0].toString() + "))";

            // Find and process certificate records
            if (revReason != null && revReason == RevocationReason.REMOVE_FROM_CRL) {
                // Unrevocation path
                for (BigInteger sn : serialNoArray) {
                    processor.addSerialNumberToUnrevoke(sn);
                }
                processor.createUnrevocationRequest();
            } else {
                // Revocation path
                processor.createCRLExtension();
                RecordPagedList<CertRecord> records = certDB.findPagedCertRecords(revokeAll, null, null);

                for (CertRecord rec : records) {
                    X509CertImpl cert = rec.getCertificate();

                    if (rec.getStatus().equals(CertRecord.STATUS_REVOKED) &&
                            (revReason == null || revReason != RevocationReason.REMOVE_FROM_CRL)) {
                        logger.info("CACMCRevReqResource: Certificate {} is already revoked",
                                cert.getSerialNumber());
                        continue;
                    }

                    processor.addCertificateToRevoke(cert);
                }

                processor.createRevocationRequest();
            }

            processor.auditChangeRequest(ILogger.SUCCESS);

        } catch (EBaseException | IOException e) {
            logger.error("CACMCRevReqResource: Error pre-processing: {}", e.getMessage(), e);
            processor.auditChangeRequest(ILogger.FAILURE);
            result.put("Status", "1");
            result.put("Error", e.getMessage());
            return Response.serverError()
                    .entity(result.toString())
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        try {
            // Process the request
            if (revReason != null && revReason == RevocationReason.REMOVE_FROM_CRL) {
                processor.processUnrevocationRequest();
            } else {
                processor.processRevocationRequest();
            }

            Request revReq = processor.getRequest();
            RequestStatus status = revReq.getRequestStatus();

            if (status == RequestStatus.COMPLETE) {
                Integer reqResult = revReq.getExtDataInInteger(Request.RESULT);

                if (reqResult != null && reqResult.equals(Request.RES_ERROR)) {
                    String[] svcErrors = revReq.getExtDataInStringArray(Request.SVCERRORS);
                    if (svcErrors != null && svcErrors.length > 0) {
                        result.put("Status", "1");
                        result.put("Error", String.join("; ", svcErrors));
                    }
                } else {
                    result.put("revoked", "yes");
                    result.put("Status", "0");
                }

                Integer updateCRLResult = revReq.getExtDataInInteger(Request.CRL_UPDATE_STATUS);
                if (updateCRLResult != null) {
                    result.put("updateCRL", updateCRLResult.equals(Request.RES_SUCCESS) ? "yes" : "no");
                    if (!updateCRLResult.equals(Request.RES_SUCCESS)) {
                        String crlError = revReq.getExtDataInString(Request.CRL_UPDATE_ERROR);
                        if (crlError != null) {
                            result.put("updateCRLError", crlError);
                        }
                    }
                }

                Integer publishCRLResult = revReq.getExtDataInInteger(Request.CRL_PUBLISH_STATUS);
                if (publishCRLResult != null) {
                    result.put("publishCRL", publishCRLResult.equals(Request.RES_SUCCESS) ? "yes" : "no");
                    if (!publishCRLResult.equals(Request.RES_SUCCESS)) {
                        String publError = revReq.getExtDataInString(Request.CRL_PUBLISH_ERROR);
                        if (publError != null) {
                            result.put("publishCRLError", publError);
                        }
                    }
                }

            } else if (status == RequestStatus.PENDING) {
                result.put("Status", "1");
                result.put("revoked", "pending");
                result.put("Error", "Request Pending");
            } else {
                result.put("Status", "1");
                result.put("revoked", "no");
                Vector<String> errors = revReq.getExtDataInStringVector(Request.ERRORS);
                if (errors != null && !errors.isEmpty()) {
                    result.put("Error", String.join("\n", errors));
                }
            }

            result.set("certificates", certsArray);
            processor.auditChangeRequestProcessed(ILogger.SUCCESS);

        } catch (EBaseException e) {
            logger.error("CACMCRevReqResource: Error processing: {}", e.getMessage(), e);
            processor.auditChangeRequestProcessed(ILogger.FAILURE);
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
