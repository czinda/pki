//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.quarkus;

import java.io.IOException;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.authentication.AuthToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.connector.IPKIMessage;
import com.netscape.certsrv.logging.AuditFormat;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.connector.HttpPKIMessage;
import com.netscape.cmscore.connector.HttpRequestEncoder;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestQueue;
import com.netscape.cmscore.request.RequestRepository;

/**
 * Abstract base JAX-RS resource replacing the legacy CloneServlet.
 * Handles clone inter-subsystem replication RPC. Clone CAs send
 * encoded PKI messages (typically revocation requests) to the
 * master CA for processing.
 *
 * Each subsystem extends this with a concrete @Path annotation
 * and provides the engine instance.
 *
 * The original CloneServlet uses client-certificate authentication
 * and a custom serialization format. This base class preserves the
 * encoded request/response format for backward compatibility with
 * existing clone infrastructure.
 */
public abstract class CloneResourceBase {

    private static final Logger logger = LoggerFactory.getLogger(CloneResourceBase.class);

    private final HttpRequestEncoder reqEncoder = new HttpRequestEncoder();

    /**
     * Return the CMSEngine for this subsystem.
     */
    protected abstract CMSEngine getEngine();

    /**
     * Return the RequestRepository for this subsystem.
     */
    protected abstract RequestRepository getRequestRepository();

    /**
     * Authenticate the clone peer and return the user ID.
     * Implementations should verify the client certificate
     * and return the authenticated user ID.
     *
     * @return the authenticated clone user ID, or null if authentication fails
     */
    protected abstract String authenticateClone();

    /**
     * Return the source identifier for the clone peer.
     * Typically the Subject DN of the clone's client certificate.
     *
     * @return the clone source identifier
     */
    protected abstract String getCloneSourceId();

    @POST
    @Consumes(MediaType.TEXT_PLAIN)
    @Produces(MediaType.TEXT_PLAIN)
    public Response processCloneRequest(String encodedRequest) {

        logger.info("CloneResourceBase: Processing clone request");

        CMSEngine engine = getEngine();

        if (!engine.isInRunningState()) {
            return Response.status(Response.Status.SERVICE_UNAVAILABLE)
                    .entity("CMS server is not ready to serve.")
                    .build();
        }

        String cloneUserId = authenticateClone();
        if (cloneUserId == null) {
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }

        String cloneSourceId = getCloneSourceId();
        if (cloneSourceId == null) {
            return Response.status(Response.Status.FORBIDDEN).build();
        }

        if (encodedRequest == null || encodedRequest.isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Missing request body")
                    .build();
        }

        IPKIMessage msg;
        IPKIMessage replyMsg;

        try {
            // Decode the incoming request
            logger.debug("CloneResourceBase: Decoding request");
            msg = (IPKIMessage) reqEncoder.decode(encodedRequest);

            // Process the request
            logger.debug("CloneResourceBase: Processing decoded request");
            replyMsg = processRequest(cloneSourceId, cloneUserId, msg);

        } catch (IOException e) {
            logger.error("CloneResourceBase: IO error processing request: {}", e.getMessage(), e);
            return Response.status(Response.Status.BAD_REQUEST).build();

        } catch (EBaseException e) {
            logger.error("CloneResourceBase: Error processing request: {}", e.getMessage(), e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }

        // Encode reply
        try {
            String encodedReply = reqEncoder.encode(replyMsg);
            return Response.ok(encodedReply, MediaType.TEXT_PLAIN).build();

        } catch (IOException e) {
            logger.error("CloneResourceBase: Error encoding reply: {}", e.getMessage(), e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Process a clone request. Finds or creates a request in the
     * request queue and processes it.
     *
     * @param source the clone source identifier
     * @param sourceUserId the authenticated user ID of the clone
     * @param msg the decoded PKI message
     * @return the reply PKI message
     */
    protected IPKIMessage processRequest(String source, String sourceUserId, IPKIMessage msg)
            throws EBaseException {

        CMSEngine engine = getEngine();
        RequestQueue queue = engine.getRequestQueue();
        RequestRepository requestRepository = getRequestRepository();
        String srcid = source + ":" + msg.getReqId();

        logger.info("CloneResourceBase: Processing request from source: {}", srcid);

        // Check if request already exists (idempotent processing)
        RequestId existingReqId = requestRepository.findRequestBySourceId(srcid);
        if (existingReqId != null) {
            Request existingReq = requestRepository.readRequest(existingReqId);
            if (existingReq == null) {
                throw new EBaseException("Cannot find request in request queue: " + existingReqId);
            }
            logger.info("CloneResourceBase: Found existing request {} for {}", existingReqId, srcid);
            IPKIMessage replyMsg = new HttpPKIMessage();
            replyMsg.fromRequest(existingReq);
            return replyMsg;
        }

        // Create new request
        Request newReq = requestRepository.createRequest(msg.getReqType());
        newReq.setSourceId(srcid);
        msg.toRequest(newReq);

        // Setting requestor type must come after copying contents
        newReq.setExtData(Request.REQUESTOR_TYPE, Request.REQUESTOR_RA);

        logger.info("CloneResourceBase: Processing remote request: {}", srcid);

        // Set user ID in session context for audit logging
        SessionContext sc = SessionContext.getContext();
        if (sc.get(SessionContext.USER_ID) == null) {
            sc.put(SessionContext.USER_ID, sourceUserId);
        }

        queue.processRequest(newReq);

        IPKIMessage replyMsg = new HttpPKIMessage();
        replyMsg.fromRequest(newReq);

        // Audit logging
        String initiative = AuditFormat.FROMRA + " trustedManagerID: " +
                sourceUserId + " remote reqID " + msg.getReqId();

        if (!newReq.getRequestStatus().equals(RequestStatus.COMPLETE)) {
            logger.info(
                    AuditFormat.NODNFORMAT,
                    newReq.getRequestType(),
                    newReq.getRequestId(),
                    initiative,
                    AuditFormat.NOAUTH,
                    newReq.getRequestStatus()
            );
        } else {
            if (newReq.getRequestType().equals(Request.CLA_CERT4CRL_REQUEST)) {
                Integer result = newReq.getExtDataInInteger(Request.RESULT);
                if (result != null && result.equals(Request.RES_ERROR)) {
                    logger.debug("CloneResourceBase: Error in CLA_CERT4CRL_REQUEST");
                } else {
                    logger.debug("CloneResourceBase: Success in CLA_CERT4CRL_REQUEST");
                }
            }
        }

        return replyMsg;
    }

    /**
     * Return a JSON error response for use by subclasses.
     */
    protected Response jsonError(String message, Response.Status status) {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode result = mapper.createObjectNode();
        result.put("Status", "1");
        result.put("Error", message);
        return Response.status(status)
                .entity(result.toString())
                .type(MediaType.APPLICATION_JSON)
                .build();
    }
}
