//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.math.BigInteger;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestRepository;

/**
 * JAX-RS resource replacing the legacy CheckRequest CMSServlet.
 * Checks the status of a certificate request and returns the cert if issued.
 * Legacy URL: /ee/ca/checkRequest
 */
@Path("ee/ca/checkRequest")
public class CACheckRequestResource {

    private static final Logger logger = LoggerFactory.getLogger(CACheckRequestResource.class);

    @Inject
    CAEngineQuarkus engineQuarkus;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response checkRequest(@QueryParam("requestId") String requestIdStr) {

        logger.info("CACheckRequestResource: Checking request status");

        CAEngine engine = engineQuarkus.getEngine();
        RequestRepository requestRepository = engine.getRequestRepository();

        if (requestIdStr == null || requestIdStr.isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"Error\":\"Missing requestId parameter\"}")
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode result = mapper.createObjectNode();

        try {
            RequestId requestId = new RequestId(requestIdStr.trim());
            Request request = requestRepository.readRequest(requestId);

            if (request == null) {
                result.put("Status", "1");
                result.put("Error", "Request not found");
                return Response.status(Response.Status.NOT_FOUND)
                        .entity(result.toString())
                        .type(MediaType.APPLICATION_JSON)
                        .build();
            }

            RequestStatus status = request.getRequestStatus();
            result.put("Status", "0");
            result.put("requestId", requestIdStr);
            result.put("requestStatus", status.toString());
            result.put("requestType", request.getRequestType());

            if (status == RequestStatus.COMPLETE) {
                Integer requestResult = request.getExtDataInInteger(Request.RESULT);
                if (requestResult != null) {
                    result.put("result", requestResult);
                }

                // If cert was issued, include it
                X509CertImpl cert = request.getExtDataInCert(Request.REQUEST_ISSUED_CERT);
                if (cert != null) {
                    result.put("serialNumber", cert.getSerialNumber().toString(16));
                    result.put("subjectDN", cert.getSubjectName().toString());
                    result.put("b64", Utils.base64encode(cert.getEncoded(), true));
                }

                String error = request.getExtDataInString(Request.ERROR);
                if (error != null) {
                    result.put("errorDetail", error);
                }

            } else if (status == RequestStatus.REJECTED) {
                String error = request.getExtDataInString(Request.ERROR);
                if (error != null) {
                    result.put("errorDetail", error);
                }
            }

        } catch (Exception e) {
            logger.error("CACheckRequestResource: Error checking request: {}", e.getMessage(), e);
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
