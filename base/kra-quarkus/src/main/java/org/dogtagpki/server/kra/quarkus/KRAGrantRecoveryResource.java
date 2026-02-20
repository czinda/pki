//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

import java.math.BigInteger;
import java.util.Hashtable;

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
import org.dogtagpki.server.kra.KRAEngineConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.cms.realm.PKIPrincipalCore;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.kra.KeyRecoveryAuthority;

import io.quarkus.security.identity.SecurityIdentity;

/**
 * JAX-RS resource replacing the legacy GrantRecovery CMSServlet.
 * Approves a key recovery request by adding agent credentials.
 *
 * When key splitting is disabled, the agent ID is resolved from the
 * authenticated security identity rather than the form parameter.
 *
 * Legacy URL: /agent/kra/grantRecovery
 */
@Path("agent/kra/grantRecovery")
public class KRAGrantRecoveryResource {

    private static final Logger logger = LoggerFactory.getLogger(KRAGrantRecoveryResource.class);

    @Inject
    KRAEngineQuarkus engineQuarkus;

    @Inject
    SecurityIdentity securityIdentity;

    @Context
    SecurityContext securityContext;

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response grantRecovery(
            @FormParam("recoveryID") String recoveryID,
            @FormParam("agentID") String agentID,
            @FormParam("agentPWD") String agentPWD) {

        logger.debug("KRAGrantRecoveryResource.grantRecovery({}, {})", recoveryID, agentID);

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode result = mapper.createObjectNode();

        KRAEngine engine = engineQuarkus.getEngine();
        KRAEngineConfig cs = engine.getConfig();
        Auditor auditor = engine.getAuditor();

        // Resolve agent ID: when not using key splitting, use the
        // authenticated user's ID instead of the form parameter
        String resolvedAgentID = agentID;
        try {
            if (!cs.getBoolean("kra.keySplitting")) {
                String authUid = resolveAuthenticatedUid();
                if (authUid != null) {
                    resolvedAgentID = authUid;
                }
            }
        } catch (EBaseException e) {
            logger.debug("KRAGrantRecoveryResource: Error checking keySplitting config", e);
        }

        // Determine audit subject ID from authenticated identity
        String auditSubjectID = resolveAuthenticatedUid();
        if (auditSubjectID == null || auditSubjectID.isEmpty()) {
            auditSubjectID = ILogger.UNIDENTIFIED;
        }

        String auditRecoveryID = normalizeAuditParam(recoveryID);
        String auditAgentID = normalizeAuditParam(resolvedAgentID);

        try {
            if (recoveryID == null || recoveryID.trim().isEmpty()) {
                result.put("error", "Missing required parameter: recoveryID");
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(result.toString())
                        .build();
            }

            KeyRecoveryAuthority kra = engine.getKRA();

            Hashtable<String, Object> params = kra.getRecoveryParams(recoveryID);

            if (params == null) {
                result.put("error", "No such recovery token found");

                logAgentLogin(auditor, auditSubjectID, auditRecoveryID, auditAgentID, ILogger.FAILURE);
                return Response.status(Response.Status.NOT_FOUND)
                        .entity(result.toString())
                        .build();
            }

            String keyID = (String) params.get("keyID");
            result.put("serialNumber", keyID);
            if (keyID != null) {
                result.put("serialNumberInHex", new BigInteger(keyID).toString(16));
            }

            kra.addDistributedCredential(recoveryID, resolvedAgentID, agentPWD);

            result.put("agentID", resolvedAgentID);
            result.put("recoveryID", recoveryID);
            result.put("status", "approved");

            logAgentLogin(auditor, auditSubjectID, auditRecoveryID, auditAgentID, ILogger.SUCCESS);

            return Response.ok(result.toString(), MediaType.APPLICATION_JSON).build();

        } catch (EBaseException e) {
            logger.error("KRAGrantRecoveryResource: Failed to grant recovery: {}", e.getMessage(), e);
            result.put("error", e.getMessage());

            logAgentLogin(auditor, auditSubjectID, auditRecoveryID, auditAgentID, ILogger.FAILURE);

            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(result.toString())
                    .build();

        } catch (Exception e) {
            logger.error("KRAGrantRecoveryResource: Unexpected error: {}", e.getMessage(), e);
            result.put("error", e.getMessage());

            logAgentLogin(auditor, auditSubjectID, auditRecoveryID, auditAgentID, ILogger.FAILURE);

            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(result.toString())
                    .build();
        }
    }

    /**
     * Resolve the authenticated user ID from the Quarkus security identity.
     */
    private String resolveAuthenticatedUid() {
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

    private void logAgentLogin(Auditor auditor, String subjectID, String recoveryID,
            String agentID, String status) {
        if (auditor != null) {
            String auditMessage = CMS.getLogMessage(
                    AuditEvent.KEY_RECOVERY_AGENT_LOGIN,
                    subjectID,
                    status,
                    recoveryID,
                    agentID);
            auditor.log(auditMessage);
        }
    }

    private String normalizeAuditParam(String value) {
        if (value != null) {
            value = value.trim();
            if (!value.isEmpty()) {
                return value;
            }
        }
        return ILogger.UNIDENTIFIED;
    }
}
