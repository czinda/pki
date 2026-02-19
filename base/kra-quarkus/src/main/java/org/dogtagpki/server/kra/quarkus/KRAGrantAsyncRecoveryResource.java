//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;

import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.kra.KRAEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.SecurityDataRecoveryStateChangeEvent;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cms.realm.PKIPrincipalCore;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.kra.KeyRecoveryAuthority;

import io.quarkus.security.identity.SecurityIdentity;

/**
 * JAX-RS resource replacing the legacy GrantAsyncRecovery CMSServlet.
 * Approves an asynchronous key recovery request by adding the agent
 * to the approval list.
 *
 * The original servlet extracts the agent UID from the auth token
 * and calls addAgentAsyncKeyRecovery to register the agent's approval.
 * Audit events are logged for both success and failure.
 *
 * Legacy URL: /agent/kra/grantAsyncRecovery
 */
@Path("agent/kra/grantAsyncRecovery")
public class KRAGrantAsyncRecoveryResource {

    private static final Logger logger = LoggerFactory.getLogger(KRAGrantAsyncRecoveryResource.class);

    @Inject
    KRAEngineQuarkus engineQuarkus;

    @Inject
    SecurityIdentity securityIdentity;

    @Context
    SecurityContext securityContext;

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response grantAsyncRecovery(@FormParam("reqID") String reqID) {

        logger.debug("KRAGrantAsyncRecoveryResource: process() begins");

        KRAEngine engine = engineQuarkus.getEngine();
        KeyRecoveryAuthority kra = engine.getKRA();
        Auditor auditor = engine.getAuditor();

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode result = mapper.createObjectNode();

        // Resolve agent ID from authenticated identity (matching original servlet behavior)
        String agentID = resolveAgentId();
        String auditSubjectID = (agentID != null && !agentID.trim().isEmpty())
                ? agentID.trim() : ILogger.UNIDENTIFIED;

        logger.debug("KRAGrantAsyncRecoveryResource: agent uid={}", agentID);
        logger.debug("KRAGrantAsyncRecoveryResource: request id={}", reqID);

        if (reqID == null || reqID.trim().isEmpty()) {
            result.put("Status", "1");
            result.put("Error", "Missing reqID parameter");
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(result.toString())
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        try {
            // Add this agent's approval to the async recovery request
            kra.addAgentAsyncKeyRecovery(reqID, agentID);

            result.put("Status", "0");
            result.put("requestID", reqID);
            result.put("agentID", agentID);

            auditor.log(new SecurityDataRecoveryStateChangeEvent(
                    auditSubjectID,
                    ILogger.SUCCESS,
                    new RequestId(reqID),
                    "approve"));

        } catch (Exception e) {
            logger.error("KRAGrantAsyncRecoveryResource: Error: {}", e.getMessage(), e);
            result.put("Status", "1");
            result.put("Error", e.getMessage());

            auditor.log(new SecurityDataRecoveryStateChangeEvent(
                    auditSubjectID,
                    ILogger.FAILURE,
                    new RequestId(reqID),
                    "approve"));

            return Response.serverError()
                    .entity(result.toString())
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        return Response.ok(result.toString(), MediaType.APPLICATION_JSON).build();
    }

    /**
     * Resolve the agent user ID from the Quarkus security identity.
     * The original servlet uses authToken.getInString("uid").
     */
    private String resolveAgentId() {
        PKIPrincipalCore pkiPrincipal = securityIdentity.getAttribute("pki.principal");
        if (pkiPrincipal != null) {
            AuthToken authToken = (AuthToken) pkiPrincipal.getAuthToken();
            if (authToken != null) {
                String uid = authToken.getInString("uid");
                if (uid != null) return uid;
            }
            return pkiPrincipal.getName();
        }

        java.security.Principal principal = securityContext.getUserPrincipal();
        if (principal != null) {
            return principal.getName();
        }
        return null;
    }
}
