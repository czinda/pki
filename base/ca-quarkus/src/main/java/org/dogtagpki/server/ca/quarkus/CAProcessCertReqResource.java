//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.math.BigInteger;

import jakarta.inject.Inject;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;

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
import com.netscape.cmscore.request.RequestQueue;
import com.netscape.cmscore.request.RequestRepository;

/**
 * JAX-RS resource replacing the legacy ProcessCertReq CMSServlet.
 * Agent operations on certificate requests: approve, reject, cancel, reassign.
 * Legacy URL: /agent/ca/processCertReq
 */
@Path("agent/ca/processCertReq")
public class CAProcessCertReqResource {

    private static final Logger logger = LoggerFactory.getLogger(CAProcessCertReqResource.class);

    @Inject
    CAEngineQuarkus engineQuarkus;

    @Context
    SecurityContext securityContext;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getRequestInfo(@QueryParam("seqNum") String seqNum) {

        logger.info("CAProcessCertReqResource: Getting request info");

        CAEngine engine = engineQuarkus.getEngine();
        RequestRepository requestRepository = engine.getRequestRepository();

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode result = mapper.createObjectNode();

        if (seqNum == null || seqNum.isEmpty()) {
            result.put("Status", "1");
            result.put("Error", "Missing seqNum parameter");
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(result.toString())
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        try {
            RequestId reqId = new RequestId(seqNum.trim());
            Request request = requestRepository.readRequest(reqId);

            if (request == null) {
                result.put("Status", "1");
                result.put("Error", "Request not found");
                return Response.status(Response.Status.NOT_FOUND)
                        .entity(result.toString())
                        .type(MediaType.APPLICATION_JSON)
                        .build();
            }

            result.put("Status", "0");
            result.put("requestId", request.getRequestId().toString());
            result.put("requestType", request.getRequestType());
            result.put("requestStatus", request.getRequestStatus().toString());
            result.put("createdOn", request.getCreationTime().getTime() / 1000);
            result.put("modifiedOn", request.getModificationTime().getTime() / 1000);

            String requestorName = request.getExtDataInString(Request.REQUESTOR_NAME);
            if (requestorName != null) {
                result.put("requestorName", requestorName);
            }

            String requestorEmail = request.getExtDataInString(Request.REQUESTOR_EMAIL);
            if (requestorEmail != null) {
                result.put("requestorEmail", requestorEmail);
            }

            // Include issued cert info if complete
            if (request.getRequestStatus() == RequestStatus.COMPLETE) {
                X509CertImpl issuedCert = request.getExtDataInCert(Request.REQUEST_ISSUED_CERT);
                if (issuedCert != null) {
                    result.put("certSerialNumber", issuedCert.getSerialNumber().toString(16));
                    result.put("certSubject", issuedCert.getSubjectDN().toString());
                    result.put("certB64", Utils.base64encode(issuedCert.getEncoded(), true));
                }
            }

        } catch (Exception e) {
            logger.error("CAProcessCertReqResource: Error: {}", e.getMessage(), e);
            result.put("Status", "1");
            result.put("Error", e.getMessage());
            return Response.serverError()
                    .entity(result.toString())
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        return Response.ok(result.toString(), MediaType.APPLICATION_JSON).build();
    }

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response processRequest(
            @FormParam("seqNum") String seqNum,
            @FormParam("op") String op,
            @FormParam("comment") String comment) {

        logger.info("CAProcessCertReqResource: Processing request op={}", op);

        CAEngine engine = engineQuarkus.getEngine();
        RequestRepository requestRepository = engine.getRequestRepository();
        RequestQueue requestQueue = engine.getRequestQueue();

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode result = mapper.createObjectNode();

        if (seqNum == null || seqNum.isEmpty()) {
            result.put("Status", "1");
            result.put("Error", "Missing seqNum parameter");
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(result.toString())
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        if (op == null || op.isEmpty()) {
            result.put("Status", "1");
            result.put("Error", "Missing op parameter");
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(result.toString())
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        try {
            RequestId reqId = new RequestId(seqNum.trim());
            Request request = requestRepository.readRequest(reqId);

            if (request == null) {
                result.put("Status", "1");
                result.put("Error", "Request not found");
                return Response.status(Response.Status.NOT_FOUND)
                        .entity(result.toString())
                        .type(MediaType.APPLICATION_JSON)
                        .build();
            }

            String agentID = securityContext.getUserPrincipal() != null ?
                    securityContext.getUserPrincipal().getName() : null;

            switch (op.toLowerCase()) {
                case "approve":
                case "accept":
                    request.setRequestStatus(RequestStatus.APPROVED);
                    if (comment != null) {
                        request.setExtData(Request.REQUESTOR_COMMENTS, comment);
                    }
                    requestQueue.processRequest(request);
                    result.put("Status", "0");
                    result.put("requestStatus", request.getRequestStatus().toString());

                    // Include issued cert if request completed
                    if (request.getRequestStatus() == RequestStatus.COMPLETE) {
                        X509CertImpl issuedCert = request.getExtDataInCert(Request.REQUEST_ISSUED_CERT);
                        if (issuedCert != null) {
                            result.put("certSerialNumber", issuedCert.getSerialNumber().toString(16));
                            result.put("certSubject", issuedCert.getSubjectDN().toString());
                            result.put("certB64", Utils.base64encode(issuedCert.getEncoded(), true));
                        }
                    }
                    break;

                case "reject":
                    request.setRequestStatus(RequestStatus.REJECTED);
                    if (comment != null) {
                        request.setExtData(Request.REQUESTOR_COMMENTS, comment);
                    }
                    requestRepository.updateRequest(request);
                    result.put("Status", "0");
                    result.put("requestStatus", "rejected");
                    break;

                case "cancel":
                    request.setRequestStatus(RequestStatus.CANCELED);
                    if (comment != null) {
                        request.setExtData(Request.REQUESTOR_COMMENTS, comment);
                    }
                    requestRepository.updateRequest(request);
                    result.put("Status", "0");
                    result.put("requestStatus", "canceled");
                    break;

                case "assign":
                    if (agentID != null) {
                        request.setExtData(Request.ASSIGNED_AGENT, agentID);
                    }
                    requestRepository.updateRequest(request);
                    result.put("Status", "0");
                    result.put("requestStatus", request.getRequestStatus().toString());
                    result.put("assignedTo", agentID);
                    break;

                case "unassign":
                    request.deleteExtData(Request.ASSIGNED_AGENT);
                    requestRepository.updateRequest(request);
                    result.put("Status", "0");
                    result.put("requestStatus", request.getRequestStatus().toString());
                    break;

                default:
                    result.put("Status", "1");
                    result.put("Error", "Unknown operation: " + op);
                    return Response.status(Response.Status.BAD_REQUEST)
                            .entity(result.toString())
                            .type(MediaType.APPLICATION_JSON)
                            .build();
            }

        } catch (Exception e) {
            logger.error("CAProcessCertReqResource: Error: {}", e.getMessage(), e);
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
