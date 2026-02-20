//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

import java.util.Hashtable;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
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
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.SecurityDataExportEvent;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cms.realm.PKIPrincipalCore;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.kra.KeyRecoveryAuthority;

import io.quarkus.security.identity.SecurityIdentity;

/**
 * JAX-RS resource replacing the legacy GetPk12 CMSServlet.
 * Gets the recovered key in PKCS#12 format.
 *
 * The original servlet requires the requesting agent to be the same
 * agent who initiated the recovery. It also logs audit events for
 * both success and failure of PKCS#12 export.
 *
 * Legacy URL: /agent/kra/getPk12
 */
@Path("agent/kra/getPk12")
public class KRAGetPk12Resource {

    private static final Logger logger = LoggerFactory.getLogger(KRAGetPk12Resource.class);

    @Inject
    KRAEngineQuarkus engineQuarkus;

    @Inject
    SecurityIdentity securityIdentity;

    @Context
    SecurityContext securityContext;

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response getPk12(@FormParam("recoveryID") String recoveryID) {

        logger.debug("KRAGetPk12Resource.getPk12({})", recoveryID);

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode errorResult = mapper.createObjectNode();

        KRAEngine engine = engineQuarkus.getEngine();
        Auditor auditor = engine.getAuditor();
        KeyRecoveryAuthority kra = engine.getKRA();

        // Determine the requesting agent identity
        String agent = resolveAgentId();

        try {
            if (recoveryID == null || recoveryID.trim().isEmpty()) {
                errorResult.put("error", "Missing required parameter: recoveryID");
                return Response.status(Response.Status.BAD_REQUEST)
                        .type(MediaType.APPLICATION_JSON)
                        .entity(errorResult.toString())
                        .build();
            }

            if (agent == null) {
                logger.error("KRAGetPk12Resource: Agent identity not found");
                errorResult.put("error", "Agent identity not found");
                return Response.status(Response.Status.UNAUTHORIZED)
                        .type(MediaType.APPLICATION_JSON)
                        .entity(errorResult.toString())
                        .build();
            }

            Hashtable<String, Object> params = kra.getRecoveryParams(recoveryID);

            if (params == null) {
                logger.error("KRAGetPk12Resource: No recovery token found for {}", recoveryID);
                errorResult.put("error", "No recovery token found for recovery ID: " + recoveryID);
                return Response.status(Response.Status.NOT_FOUND)
                        .type(MediaType.APPLICATION_JSON)
                        .entity(errorResult.toString())
                        .build();
            }

            // Verify the requesting agent matches the initiating agent
            String initAgent = (String) params.get("agent");
            if (!agent.equals(initAgent)) {
                logger.error("KRAGetPk12Resource: Agent {} not authorized; recovery initiated by {}", agent, initAgent);

                auditExport(auditor, agent, recoveryID, ILogger.FAILURE);

                errorResult.put("error", "Agent not authorized for this recovery");
                return Response.status(Response.Status.FORBIDDEN)
                        .type(MediaType.APPLICATION_JSON)
                        .entity(errorResult.toString())
                        .build();
            }

            // Retrieve PKCS#12 data
            byte[] pkcs12 = kra.getPk12(recoveryID);

            if (pkcs12 != null) {
                kra.destroyRecoveryParams(recoveryID);

                auditExport(auditor, agent, recoveryID, ILogger.SUCCESS);

                return Response.ok(pkcs12, "application/x-pkcs12").build();
            }

            // Check for error in recovery process
            String error = kra.getError(recoveryID);
            if (error != null) {
                auditExport(auditor, agent, recoveryID, ILogger.FAILURE);

                errorResult.put("error", error);
                errorResult.put("recoveryID", recoveryID);
                if (params.get("keyID") != null) {
                    errorResult.put("serialNumber", (String) params.get("keyID"));
                }
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                        .type(MediaType.APPLICATION_JSON)
                        .entity(errorResult.toString())
                        .build();
            }

            // PKCS#12 hasn't been created yet
            ObjectNode pendingResult = mapper.createObjectNode();
            pendingResult.put("status", "pending");
            pendingResult.put("recoveryID", recoveryID);
            if (params.get("keyID") != null) {
                pendingResult.put("serialNumber", (String) params.get("keyID"));
            }
            return Response.status(Response.Status.ACCEPTED)
                    .type(MediaType.APPLICATION_JSON)
                    .entity(pendingResult.toString())
                    .build();

        } catch (EBaseException e) {
            logger.error("KRAGetPk12Resource: Failed to get PKCS#12: {}", e.getMessage(), e);

            if (agent != null && recoveryID != null) {
                auditExport(auditor, agent, recoveryID, ILogger.FAILURE);
            }

            errorResult.put("error", e.getMessage());
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .type(MediaType.APPLICATION_JSON)
                    .entity(errorResult.toString())
                    .build();
        }
    }

    /**
     * Resolve the agent user ID from the Quarkus security identity.
     */
    private String resolveAgentId() {
        PKIPrincipalCore pkiPrincipal = securityIdentity.getAttribute("pki.principal");
        if (pkiPrincipal != null) {
            AuthToken authToken = (AuthToken) pkiPrincipal.getAuthToken();
            if (authToken != null) {
                String uid = authToken.getInString("userid");
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

    /**
     * Log a SecurityDataExportEvent audit record.
     */
    private void auditExport(Auditor auditor, String agent, String recoveryID, String status) {
        if (auditor != null) {
            auditor.log(new SecurityDataExportEvent(
                    agent,
                    status,
                    new RequestId(recoveryID),
                    null,
                    null,
                    null));
        }
    }
}
