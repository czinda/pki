//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

import java.math.BigInteger;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.kra.KRAEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.security.Credential;
import com.netscape.kra.KeyRecoveryAuthority;

/**
 * JAX-RS resource replacing the legacy GetApprovalStatus CMSServlet.
 * Checks whether a key recovery request has been approved by the
 * required number of agents.
 *
 * Legacy URL: /agent/kra/getApprovalStatus
 */
@Path("agent/kra/getApprovalStatus")
public class KRAGetApprovalStatusResource {

    private static final Logger logger = LoggerFactory.getLogger(KRAGetApprovalStatusResource.class);

    @Inject
    KRAEngineQuarkus engineQuarkus;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getApprovalStatus(@QueryParam("recoveryID") String recoveryID) {

        logger.debug("KRAGetApprovalStatusResource.getApprovalStatus({})", recoveryID);

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode result = mapper.createObjectNode();

        try {
            if (recoveryID == null || recoveryID.trim().isEmpty()) {
                result.put("error", "Missing required parameter: recoveryID");
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(result.toString())
                        .build();
            }

            KRAEngine engine = engineQuarkus.getEngine();
            KeyRecoveryAuthority kra = engine.getKRA();

            result.put("recoveryID", recoveryID);

            Hashtable<String, Object> params = kra.getRecoveryParams(recoveryID);

            if (params == null) {
                logger.error("KRAGetApprovalStatusResource: No recovery token found for {}", recoveryID);
                result.put("error", "No recovery token found for recovery ID: " + recoveryID);
                return Response.status(Response.Status.NOT_FOUND)
                        .entity(result.toString())
                        .build();
            }

            String keyID = (String) params.get("keyID");
            result.put("serialNumber", keyID);
            if (keyID != null) {
                result.put("serialNumberInHex", new BigInteger(keyID).toString(16));
            }

            int requiredNumber = kra.getNoOfRequiredAgents();
            result.put("noOfRequiredAgents", requiredNumber);

            // Get list of agents who have approved
            Vector<Credential> dc = kra.getAppAgents(recoveryID);
            ArrayNode agentList = mapper.createArrayNode();

            if (dc != null) {
                Enumeration<Credential> agents = dc.elements();
                while (agents.hasMoreElements()) {
                    Credential cred = agents.nextElement();
                    ObjectNode agentNode = mapper.createObjectNode();
                    agentNode.put("agentName", cred.getIdentifier());
                    agentList.add(agentNode);
                }
            }

            result.set("approvalAgents", agentList);
            result.put("approvalCount", agentList.size());

            if (dc != null && dc.size() >= requiredNumber) {
                // All approvals received, check for PKCS#12
                byte[] pkcs12 = kra.getPk12(recoveryID);

                if (pkcs12 != null) {
                    result.put("status", "complete");
                } else {
                    String error = kra.getError(recoveryID);
                    if (error != null) {
                        result.put("status", "error");
                        result.put("error", error);
                    } else {
                        // PKCS#12 is still being generated
                        result.put("status", "processing");
                    }
                }
            } else {
                result.put("status", "pending");
            }

            return Response.ok(result.toString(), MediaType.APPLICATION_JSON).build();

        } catch (EBaseException e) {
            logger.error("KRAGetApprovalStatusResource: Failed to get approval status: {}", e.getMessage(), e);
            result.put("error", e.getMessage());
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(result.toString())
                    .build();
        }
    }
}
