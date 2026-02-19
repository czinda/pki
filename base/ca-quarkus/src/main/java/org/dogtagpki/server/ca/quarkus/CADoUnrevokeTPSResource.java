//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.math.BigInteger;
import java.util.Locale;
import java.util.StringTokenizer;
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
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.ca.CRLIssuingPoint;
import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.logging.AuditFormat;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.CertStatusChangeRequestEvent;
import com.netscape.certsrv.logging.event.CertStatusChangeRequestProcessedEvent;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.servlet.cert.RevocationProcessor;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.ldap.CAPublisherProcessor;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmscore.request.CertRequestRepository;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestQueue;

/**
 * JAX-RS resource replacing the legacy DoUnrevokeTPS CMSServlet.
 * Takes certificates off-hold (unrevokes) specifically for TPS token operations.
 * TPS communicates via form-encoded parameters and expects a form-encoded response
 * with status and error fields.
 *
 * Legacy URL: /ee/ca/doUnrevokeTPS
 */
@Path("ee/ca/doUnrevokeTPS")
public class CADoUnrevokeTPSResource {

    private static final Logger logger = LoggerFactory.getLogger(CADoUnrevokeTPSResource.class);

    private static final String OFF_HOLD = "off-hold";
    private static final int OFF_HOLD_REASON = 6;

    @Inject
    CAEngineQuarkus engineQuarkus;

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response doUnrevokeTPS(@FormParam("serialNumber") String serialNumString) {

        logger.info("CADoUnrevokeTPSResource: Processing TPS unrevocation request");

        CAEngine engine = engineQuarkus.getEngine();
        CertificateRepository certRepository = engine.getCertificateRepository();
        CAPublisherProcessor publisherProcessor = engine.getPublisherProcessor();
        RequestQueue requestQueue = engine.getRequestQueue();
        Auditor auditor = engine.getAuditor();

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode result = mapper.createObjectNode();

        BigInteger[] serialNumbers;
        try {
            serialNumbers = parseSerialNumbers(serialNumString);
        } catch (NumberFormatException e) {
            logger.error("CADoUnrevokeTPSResource: Invalid serial number format");
            result.put("status", 3);
            result.put("error", "Invalid serial number format");
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(result.toString())
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        String auditSerialNumber = "0x" + serialNumbers[0].toString(16);
        String auditRequestType = OFF_HOLD;
        String auditReasonNum = String.valueOf(OFF_HOLD_REASON);
        RequestStatus auditApprovalStatus = null;

        Request unrevReq = null;
        X509CertImpl[] certs;

        try {
            certs = new X509CertImpl[serialNumbers.length];
            StringBuilder snList = new StringBuilder();

            for (int i = 0; i < serialNumbers.length; i++) {
                certs[i] = certRepository.getX509Certificate(serialNumbers[i]);
                if (snList.length() > 0) snList.append(", ");
                snList.append("0x").append(serialNumbers[i].toString(16));
            }

            CertRequestRepository certRequestRepository = engine.getCertRequestRepository();
            unrevReq = certRequestRepository.createRequest(Request.UNREVOCATION_REQUEST);

            auditor.log(new CertStatusChangeRequestEvent(
                    auditSubjectID(),
                    ILogger.SUCCESS,
                    unrevReq,
                    auditSerialNumber,
                    auditRequestType));

            unrevReq.setExtData(Request.REQ_TYPE, Request.UNREVOCATION_REQUEST);
            unrevReq.setExtData(Request.OLD_SERIALS, serialNumbers);
            unrevReq.setExtData(Request.REQUESTOR_TYPE, Request.REQUESTOR_AGENT);

        } catch (EBaseException e) {
            logger.error("CADoUnrevokeTPSResource: Error creating unrevocation request", e);
            auditor.log(new CertStatusChangeRequestEvent(
                    auditSubjectID(),
                    ILogger.FAILURE,
                    unrevReq,
                    auditSerialNumber,
                    auditRequestType));

            result.put("status", 3);
            result.put("error", e.getMessage());
            return Response.serverError()
                    .entity(result.toString())
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        try {
            requestQueue.processRequest(unrevReq);
            auditApprovalStatus = unrevReq.getRequestStatus();
            RequestStatus status = unrevReq.getRequestStatus();

            if (status == RequestStatus.COMPLETE ||
                    (unrevReq.getRequestType().equals(Request.CLA_UNCERT4CRL_REQUEST) &&
                     status == RequestStatus.SVC_PENDING)) {

                Integer reqResult = unrevReq.getExtDataInInteger(Request.RESULT);

                if (reqResult != null && reqResult.equals(Request.RES_SUCCESS)) {
                    result.put("status", 0);
                    result.put("error", "");

                    if (certs[0] != null) {
                        logger.info(
                                AuditFormat.DOUNREVOKEFORMAT.toString(),
                                unrevReq.getRequestId(),
                                "TPS",
                                "completed",
                                certs[0].getSubjectName(),
                                "0x" + serialNumbers[0].toString(16));
                    }
                } else {
                    String error = unrevReq.getExtDataInString(Request.ERROR);
                    result.put("status", 3);
                    result.put("error", error != null ? error : "Unknown error");
                }

                // Check CRL update status
                Integer updateCRLResult = unrevReq.getExtDataInInteger(Request.CRL_UPDATE_STATUS);
                if (updateCRLResult != null && !updateCRLResult.equals(Request.RES_SUCCESS)) {
                    String crlError = unrevReq.getExtDataInString(Request.CRL_UPDATE_ERROR);
                    if (crlError != null) {
                        result.put("status", 3);
                        result.put("error", crlError);
                    }

                    Integer publishCRLResult = unrevReq.getExtDataInInteger(Request.CRL_PUBLISH_STATUS);
                    if (publishCRLResult != null && !publishCRLResult.equals(Request.RES_SUCCESS)) {
                        String publError = unrevReq.getExtDataInString(Request.CRL_PUBLISH_ERROR);
                        if (publError != null) {
                            result.put("status", 3);
                            result.put("error", publError);
                        }
                    }
                }

                // Check per-CRL-issuing-point update/publish status
                for (CRLIssuingPoint crl : engine.getCRLIssuingPoints()) {
                    String crlId = crl.getId();
                    if (crlId.equals(CertificateAuthority.PROP_MASTER_CRL)) continue;

                    String updateStatusStr = crl.getCrlUpdateStatusStr();
                    Integer updateResult = unrevReq.getExtDataInInteger(updateStatusStr);
                    if (updateResult != null && !updateResult.equals(Request.RES_SUCCESS)) {
                        String updateErrorStr = crl.getCrlUpdateErrorStr();
                        String error = unrevReq.getExtDataInString(updateErrorStr);
                        if (error != null) {
                            result.put("status", 3);
                            result.put("error", error);
                        }
                    }
                }

                // Check LDAP publishing status
                if (publisherProcessor != null && publisherProcessor.ldapEnabled()) {
                    Integer[] ldapPublishStatus = unrevReq.getExtDataInIntegerArray("ldapPublishStatus");
                    if (ldapPublishStatus != null && ldapPublishStatus[0] != Request.RES_SUCCESS) {
                        result.put("status", 3);
                        result.put("error", "Problem in publishing to LDAP");
                    }
                } else if (publisherProcessor == null || !publisherProcessor.ldapEnabled()) {
                    result.put("status", 3);
                    result.put("error", "LDAP Publisher not enabled");
                }

            } else if (status == RequestStatus.PENDING) {
                result.put("status", 2);
                result.put("error", status.toString());
            } else {
                result.put("status", 2);
                result.put("error", "Undefined request status");
            }

            if (auditApprovalStatus == RequestStatus.COMPLETE ||
                    auditApprovalStatus == RequestStatus.REJECTED ||
                    auditApprovalStatus == RequestStatus.CANCELED) {
                auditor.log(new CertStatusChangeRequestProcessedEvent(
                        auditSubjectID(),
                        ILogger.SUCCESS,
                        unrevReq,
                        auditSerialNumber,
                        auditRequestType,
                        auditReasonNum,
                        auditApprovalStatus));
            }

        } catch (EBaseException e) {
            logger.error("CADoUnrevokeTPSResource: Error processing unrevocation", e);

            if (auditApprovalStatus == RequestStatus.COMPLETE ||
                    auditApprovalStatus == RequestStatus.REJECTED ||
                    auditApprovalStatus == RequestStatus.CANCELED) {
                auditor.log(new CertStatusChangeRequestProcessedEvent(
                        auditSubjectID(),
                        ILogger.FAILURE,
                        unrevReq,
                        auditSerialNumber,
                        auditRequestType,
                        auditReasonNum,
                        auditApprovalStatus));
            }

            result.put("status", 3);
            result.put("error", e.getMessage());
            return Response.serverError()
                    .entity(result.toString())
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        return Response.ok(result.toString(), MediaType.APPLICATION_JSON).build();
    }

    private BigInteger[] parseSerialNumbers(String serialNumString) {
        StringTokenizer snList = new StringTokenizer(serialNumString, " ");
        Vector<BigInteger> biList = new Vector<>();

        while (snList.hasMoreTokens()) {
            String snStr = snList.nextToken().trim();
            BigInteger bi;
            if (snStr.startsWith("0x") || snStr.startsWith("0X")) {
                bi = new BigInteger(snStr.substring(2), 16);
            } else {
                bi = new BigInteger(snStr);
            }
            if (bi.compareTo(BigInteger.ZERO) < 0) {
                throw new NumberFormatException();
            }
            biList.addElement(bi);
        }

        if (biList.isEmpty()) {
            throw new NumberFormatException();
        }

        return biList.toArray(new BigInteger[0]);
    }

    private String auditSubjectID() {
        return ILogger.UNIDENTIFIED;
    }
}
