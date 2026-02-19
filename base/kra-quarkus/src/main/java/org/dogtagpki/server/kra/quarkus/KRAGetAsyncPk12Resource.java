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
import com.netscape.certsrv.logging.event.SecurityDataExportEvent;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cms.realm.PKIPrincipalCore;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestRepository;
import com.netscape.kra.KeyRecoveryAuthority;

import io.quarkus.security.identity.SecurityIdentity;

/**
 * JAX-RS resource replacing the legacy GetAsyncPk12 CMSServlet.
 * Retrieves the recovered key in PKCS#12 format for asynchronous
 * key recovery requests.
 *
 * The original servlet validates that:
 * 1. The requesting agent is the same agent who initiated the recovery
 * 2. All required recovery agents have approved the request
 * 3. The PKCS#12 password is provided and confirmed
 *
 * Audit events are logged for both success and failure of the export.
 *
 * Legacy URL: /agent/kra/getAsyncPk12
 */
@Path("agent/kra/getAsyncPk12")
public class KRAGetAsyncPk12Resource {

    private static final Logger logger = LoggerFactory.getLogger(KRAGetAsyncPk12Resource.class);

    @Inject
    KRAEngineQuarkus engineQuarkus;

    @Inject
    SecurityIdentity securityIdentity;

    @Context
    SecurityContext securityContext;

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response getAsyncPk12(
            @FormParam("reqID") String reqID,
            @FormParam("p12Password") String password,
            @FormParam("p12PasswordAgain") String passwordAgain) {

        logger.info("KRAGetAsyncPk12Resource: Getting async PKCS12");

        KRAEngine engine = engineQuarkus.getEngine();
        KeyRecoveryAuthority kra = engine.getKRA();
        RequestRepository requestRepository = engine.getRequestRepository();
        Auditor auditor = engine.getAuditor();

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode errorResult = mapper.createObjectNode();

        // Determine the requesting agent identity
        String agent = resolveAgentId();

        if (agent == null) {
            logger.error("KRAGetAsyncPk12Resource: Agent identity not found");
            errorResult.put("Status", "1");
            errorResult.put("Error", "Agent identity not found");
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity(errorResult.toString())
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        if (reqID == null || reqID.trim().isEmpty()) {
            errorResult.put("Status", "1");
            errorResult.put("Error", "Missing reqID parameter");
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(errorResult.toString())
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        try {
            // Verify the requesting agent is the init agent for this recovery
            String initAgent = kra.getInitAgentAsyncKeyRecovery(reqID);

            if ("undefined".equals(initAgent) || !agent.equals(initAgent)) {
                logger.error("KRAGetAsyncPk12Resource: Agent {} not authorized; " +
                        "recovery initiated by {}", agent, initAgent);

                auditExport(auditor, agent, reqID, ILogger.FAILURE);

                errorResult.put("Status", "1");
                errorResult.put("Error", "Agent not authorized for this recovery request");
                return Response.status(Response.Status.FORBIDDEN)
                        .entity(errorResult.toString())
                        .type(MediaType.APPLICATION_JSON)
                        .build();
            }

            // Verify all required recovery agents have approved
            if (!kra.isApprovedAsyncKeyRecovery(reqID)) {
                logger.error("KRAGetAsyncPk12Resource: Required number of recovery agents not met");

                auditExport(auditor, agent, reqID, ILogger.FAILURE);

                errorResult.put("Status", "1");
                errorResult.put("Error", "Required number of recovery agents not met");
                return Response.status(Response.Status.FORBIDDEN)
                        .entity(errorResult.toString())
                        .type(MediaType.APPLICATION_JSON)
                        .build();
            }

            // Validate PKCS#12 password
            if (password == null || password.isEmpty()) {
                errorResult.put("Status", "1");
                errorResult.put("Error", "PKCS12 password not found");
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(errorResult.toString())
                        .type(MediaType.APPLICATION_JSON)
                        .build();
            }
            if (passwordAgain == null || !passwordAgain.equals(password)) {
                errorResult.put("Status", "1");
                errorResult.put("Error", "PKCS12 password not matched");
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(errorResult.toString())
                        .type(MediaType.APPLICATION_JSON)
                        .build();
            }

            // Read the recovery request and perform key recovery
            Request request = requestRepository.readRequest(new RequestId(reqID));
            if (request == null) {
                auditExport(auditor, agent, reqID, ILogger.FAILURE);

                errorResult.put("Status", "1");
                errorResult.put("Error", "Recovery request not found");
                return Response.status(Response.Status.NOT_FOUND)
                        .entity(errorResult.toString())
                        .type(MediaType.APPLICATION_JSON)
                        .build();
            }

            byte[] pkcs12 = kra.doKeyRecovery(request, password);

            if (pkcs12 != null) {
                auditExport(auditor, agent, reqID, ILogger.SUCCESS);

                return Response.ok(pkcs12, "application/x-pkcs12")
                        .header("Content-Disposition", "attachment; filename=keys.p12")
                        .build();
            }

            // Check for error in recovery process
            String error = kra.getError(reqID);
            if (error != null) {
                auditExport(auditor, agent, reqID, ILogger.FAILURE);

                errorResult.put("Status", "1");
                errorResult.put("Error", error);
                return Response.serverError()
                        .entity(errorResult.toString())
                        .type(MediaType.APPLICATION_JSON)
                        .build();
            }

            // PKCS#12 hasn't been created yet
            auditExport(auditor, agent, reqID, ILogger.FAILURE);

            errorResult.put("Status", "1");
            errorResult.put("Error", "PKCS12 data not yet available");
            return Response.status(Response.Status.ACCEPTED)
                    .entity(errorResult.toString())
                    .type(MediaType.APPLICATION_JSON)
                    .build();

        } catch (Exception e) {
            logger.error("KRAGetAsyncPk12Resource: Error: {}", e.getMessage(), e);

            if (agent != null && reqID != null) {
                auditExport(auditor, agent, reqID, ILogger.FAILURE);
            }

            errorResult.put("Status", "1");
            errorResult.put("Error", e.getMessage());
            return Response.serverError()
                    .entity(errorResult.toString())
                    .type(MediaType.APPLICATION_JSON)
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
    private void auditExport(Auditor auditor, String agent, String reqID, String status) {
        if (auditor != null) {
            auditor.log(new SecurityDataExportEvent(
                    agent,
                    status,
                    new RequestId(reqID),
                    null,
                    null,
                    null));
        }
    }
}
