//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Locale;
import java.util.Vector;

import jakarta.inject.Inject;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;

import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.x509.RevocationReason;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.ca.CRLIssuingPoint;
import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.realm.PKIPrincipalCore;
import com.netscape.cms.servlet.cert.RevocationProcessor;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.ldap.CAPublisherProcessor;
import com.netscape.cmscore.request.Request;

import io.quarkus.security.identity.SecurityIdentity;

/**
 * JAX-RS resource replacing the legacy DoRevoke CMSServlet.
 * Revokes certificates based on serial number and revocation reason.
 * Legacy URL: /ee/ca/doRevoke
 */
@Path("ee/ca/doRevoke")
public class CADoRevokeResource {

    private static final Logger logger = LoggerFactory.getLogger(CADoRevokeResource.class);

    @Inject
    CAEngineQuarkus engineQuarkus;

    @Inject
    SecurityIdentity securityIdentity;

    @Context
    SecurityContext securityContext;

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response doRevoke(
            @FormParam("serialNumber") String serialNumberStr,
            @FormParam("revocationReason") String reasonStr,
            @FormParam("totalRecordCount") String totalRecordCountStr,
            @FormParam("verifiedRecordCount") String verifiedRecordCountStr,
            @FormParam("invalidityDate") String invalidityDateStr,
            @FormParam("revokeAll") String revokeAll,
            @FormParam("nonce") String nonces,
            @FormParam("comments") String comments) {

        logger.info("CADoRevokeResource: Processing revocation request");

        CAEngine engine = engineQuarkus.getEngine();
        CertificateRepository certDB = engine.getCertificateRepository();
        CAPublisherProcessor publisherProcessor = engine.getPublisherProcessor();

        int reason = -1;
        int totalRecordCount = -1;
        int verifiedRecordCount = -1;
        Date invalidityDate = null;

        try {
            if (reasonStr != null) reason = Integer.parseInt(reasonStr);
            if (totalRecordCountStr != null) totalRecordCount = Integer.parseInt(totalRecordCountStr);
            if (verifiedRecordCountStr != null) verifiedRecordCount = Integer.parseInt(verifiedRecordCountStr);
            if (invalidityDateStr != null) {
                long l = Long.parseLong(invalidityDateStr);
                if (l > 0) invalidityDate = new Date(l);
            }
        } catch (NumberFormatException e) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"Error\":\"Invalid number format\"}")
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        BigInteger eeSerialNumber = parseSerialNumber(serialNumberStr);

        RevocationProcessor processor = new RevocationProcessor("CADoRevokeResource", Locale.getDefault());
        processor.setCMSEngine(engine);
        processor.init();

        processor.setStartTime(new Date().getTime());
        processor.setSerialNumber(eeSerialNumber == null ? null : new CertId(eeSerialNumber));

        RevocationReason revReason = RevocationReason.valueOf(reason);
        processor.setRevocationReason(revReason);
        processor.setRequestType(
                revReason == RevocationReason.CERTIFICATE_HOLD
                        ? RevocationProcessor.ON_HOLD : RevocationProcessor.REVOKE);

        processor.setInvalidityDate(invalidityDate);
        processor.setComments(comments);
        processor.setAuthority(engine.getCA());

        Hashtable<BigInteger, Long> nonceMap = new Hashtable<>();

        if (engine.getEnableNonces() && nonces != null) {
            for (String s : nonces.split(",")) {
                String[] elements = s.split(":");
                BigInteger sn = new BigInteger(elements[0].trim());
                Long nonce = Long.valueOf(elements[1].trim());
                nonceMap.put(sn, nonce);
            }
        }

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode result = mapper.createObjectNode();
        ArrayNode certsArray = mapper.createArrayNode();

        try {
            processor.createCRLExtension();

            int timeLimits = 30;
            Enumeration<CertRecord> e = certDB.searchCertificates(revokeAll, totalRecordCount, timeLimits);

            while (e != null && e.hasMoreElements()) {
                CertRecord targetRecord = e.nextElement();
                X509CertImpl targetCert = targetRecord.getCertificate();

                if (eeSerialNumber != null &&
                    eeSerialNumber.equals(targetCert.getSerialNumber()) &&
                    targetRecord.getStatus().equals(CertRecord.STATUS_REVOKED)) {
                    return Response.status(Response.Status.CONFLICT)
                            .entity("{\"Error\":\"Certificate already revoked\"}")
                            .type(MediaType.APPLICATION_JSON)
                            .build();
                }

                ObjectNode certNode = mapper.createObjectNode();
                certNode.put("serialNumber", targetCert.getSerialNumber().toString(16));

                try {
                    processor.validateCertificateToRevoke(null, targetRecord, false);
                    processor.addCertificateToRevoke(targetCert);
                    certNode.put("status", "valid");
                } catch (PKIException ex) {
                    certNode.put("status", "error");
                    certNode.put("error", ex.getMessage());
                }

                certsArray.add(certNode);
            }

            int count = processor.getCertificates().size();
            if (count == 0) {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity("{\"Error\":\"No certificates found to revoke\"}")
                        .type(MediaType.APPLICATION_JSON)
                        .build();
            }

            processor.createRevocationRequest();
            processor.auditChangeRequest(ILogger.SUCCESS);

        } catch (ForbiddenException e) {
            logger.warn("CADoRevokeResource: Forbidden: {}", e.getMessage());
            return Response.status(Response.Status.FORBIDDEN)
                    .entity("{\"Error\":\"" + e.getMessage() + "\"}")
                    .type(MediaType.APPLICATION_JSON)
                    .build();

        } catch (EBaseException | IOException e) {
            logger.error("CADoRevokeResource: Error pre-processing revocation: {}", e.getMessage(), e);
            processor.auditChangeRequest(ILogger.FAILURE);
            return Response.serverError()
                    .entity("{\"Error\":\"" + e.getMessage() + "\"}")
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        try {
            processor.processRevocationRequest();
            Request revReq = processor.getRequest();
            RequestStatus status = revReq.getRequestStatus();

            if (status == RequestStatus.COMPLETE ||
                (status == RequestStatus.SVC_PENDING &&
                 revReq.getRequestType().equals(Request.CLA_CERT4CRL_REQUEST))) {

                result.put("Status", "0");
                result.put("revoked", "yes");
                result.set("certificates", certsArray);

                Integer updateCRLResult = revReq.getExtDataInInteger(Request.CRL_UPDATE_STATUS);
                if (updateCRLResult != null) {
                    result.put("updateCRL", updateCRLResult.equals(Request.RES_SUCCESS) ? "yes" : "no");
                }

            } else {
                result.put("Status", "1");
                result.put("revoked", status == RequestStatus.PENDING ? "pending" : "no");

                Vector<String> errors = revReq.getExtDataInStringVector(Request.ERRORS);
                if (errors != null && !errors.isEmpty()) {
                    result.put("Error", String.join("\n", errors));
                }
            }

            processor.auditChangeRequestProcessed(ILogger.SUCCESS);

        } catch (EBaseException e) {
            logger.error("CADoRevokeResource: Error processing revocation: {}", e.getMessage(), e);
            processor.auditChangeRequestProcessed(ILogger.FAILURE);
            return Response.serverError()
                    .entity("{\"Error\":\"" + e.getMessage() + "\"}")
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        return Response.ok(result.toString(), MediaType.APPLICATION_JSON).build();
    }

    private BigInteger parseSerialNumber(String serialNumber) {
        if (StringUtils.isEmpty(serialNumber)) return null;
        serialNumber = serialNumber.trim();
        try {
            return new BigInteger(serialNumber, 10);
        } catch (NumberFormatException e) {
            // ignore
        }
        try {
            return new BigInteger(serialNumber, 16);
        } catch (NumberFormatException e) {
            // ignore
        }
        throw new NumberFormatException("Invalid serial number: " + serialNumber);
    }
}
