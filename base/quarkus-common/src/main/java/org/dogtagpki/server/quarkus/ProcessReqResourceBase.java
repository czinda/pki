//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.quarkus;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestRepository;

/**
 * Base JAX-RS resource replacing the legacy ProcessReq CMSServlet.
 * Displays generic request detail.
 */
public abstract class ProcessReqResourceBase {

    private static final Logger logger = LoggerFactory.getLogger(ProcessReqResourceBase.class);

    protected abstract CMSEngine getEngine();

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response processReq(@QueryParam("seqNum") String seqNum) {

        logger.info("ProcessReqResourceBase: Getting request detail");

        CMSEngine engine = getEngine();
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

            String requestorComments = request.getExtDataInString(Request.REQUESTOR_COMMENTS);
            if (requestorComments != null) {
                result.put("requestorComments", requestorComments);
            }

            Integer resultCode = request.getExtDataInInteger(Request.RESULT);
            if (resultCode != null) {
                result.put("result", resultCode);
            }

        } catch (Exception e) {
            logger.error("ProcessReqResourceBase: Error: {}", e.getMessage(), e);
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
