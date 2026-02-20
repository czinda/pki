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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.servlet.cert.RevocationProcessor;
import com.netscape.cmscore.request.Request;

/**
 * JAX-RS resource replacing the legacy DoUnrevoke CMSServlet.
 * Takes certificates off-hold (unrevokes certificates that were placed on hold).
 * Legacy URL: /agent/ca/doUnrevoke
 */
@Path("agent/ca/doUnrevoke")
public class CADoUnrevokeResource {

    private static final Logger logger = LoggerFactory.getLogger(CADoUnrevokeResource.class);

    @Inject
    CAEngineQuarkus engineQuarkus;

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response doUnrevoke(@FormParam("serialNumber") String serialNumString) {

        logger.info("CADoUnrevokeResource: Processing unrevocation request");

        CAEngine engine = engineQuarkus.getEngine();

        BigInteger[] serialNumbers;
        try {
            serialNumbers = parseSerialNumbers(serialNumString);
        } catch (NumberFormatException e) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"Error\":\"Invalid serial number format\"}")
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        RevocationProcessor processor = new RevocationProcessor("CADoUnrevokeResource", Locale.getDefault());
        processor.setCMSEngine(engine);
        processor.init();

        processor.setSerialNumber(new CertId(serialNumbers[0]));
        processor.setRevocationReason(RevocationReason.CERTIFICATE_HOLD);
        processor.setRequestType(RevocationProcessor.OFF_HOLD);
        processor.setAuthority(engine.getCA());

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode result = mapper.createObjectNode();

        try {
            StringBuilder snList = new StringBuilder();
            for (BigInteger serialNumber : serialNumbers) {
                processor.addSerialNumberToUnrevoke(serialNumber);
                if (snList.length() > 0) snList.append(", ");
                snList.append("0x").append(serialNumber.toString(16));
            }
            result.put("serialNumber", snList.toString());

            processor.createUnrevocationRequest();
            processor.auditChangeRequest(ILogger.SUCCESS);

        } catch (EBaseException e) {
            logger.error("CADoUnrevokeResource: Error pre-processing: {}", e.getMessage(), e);
            processor.auditChangeRequest(ILogger.FAILURE);
            return Response.serverError()
                    .entity("{\"Error\":\"" + e.getMessage() + "\"}")
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        try {
            processor.processUnrevocationRequest();
            Request unrevReq = processor.getRequest();
            RequestStatus status = unrevReq.getRequestStatus();

            if (status == RequestStatus.COMPLETE ||
                (status == RequestStatus.SVC_PENDING &&
                 unrevReq.getRequestType().equals(Request.CLA_UNCERT4CRL_REQUEST))) {

                Integer reqResult = unrevReq.getExtDataInInteger(Request.RESULT);
                if (reqResult != null && reqResult.equals(Request.RES_SUCCESS)) {
                    result.put("Status", "0");
                    result.put("unrevoked", "yes");
                } else {
                    result.put("Status", "1");
                    result.put("unrevoked", "no");
                    String error = unrevReq.getExtDataInString(Request.ERROR);
                    if (error != null) result.put("Error", error);
                }

                Integer updateCRLResult = unrevReq.getExtDataInInteger(Request.CRL_UPDATE_STATUS);
                if (updateCRLResult != null) {
                    result.put("updateCRL", updateCRLResult.equals(Request.RES_SUCCESS) ? "yes" : "no");
                }

            } else if (status == RequestStatus.PENDING) {
                result.put("Status", "1");
                result.put("unrevoked", "pending");
                result.put("Error", "Request Pending");
            } else {
                result.put("Status", "1");
                result.put("unrevoked", "no");
                result.put("Error", "Request Status Error");
            }

            processor.auditChangeRequestProcessed(ILogger.SUCCESS);

        } catch (EBaseException e) {
            logger.error("CADoUnrevokeResource: Error processing: {}", e.getMessage(), e);
            processor.auditChangeRequestProcessed(ILogger.FAILURE);
            return Response.serverError()
                    .entity("{\"Error\":\"" + e.getMessage() + "\"}")
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
}
