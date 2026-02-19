//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.quarkus;

import java.util.Date;
import java.util.Enumeration;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.certsrv.authentication.AuthMgrPlugin;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.authentication.AuthSubsystem;

/**
 * Base JAX-RS resource replacing the legacy DynamicVariablesServlet CMSServlet.
 * Returns dynamic configuration variables for the subsystem.
 */
public abstract class DynamicVariablesResourceBase {

    private static final Logger logger = LoggerFactory.getLogger(DynamicVariablesResourceBase.class);

    protected abstract CMSEngine getEngine();

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getDynamicVariables() {

        logger.debug("DynamicVariablesResourceBase: Getting dynamic variables");

        CMSEngine engine = getEngine();

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode result = mapper.createObjectNode();

        try {
            result.put("Status", "0");
            result.put("serverDate", new Date().getTime());
            result.put("subsystemName", engine.getName());

            String eeSSLPort = engine.getEESSLPort();
            String eeNonSSLPort = engine.getEENonSSLPort();
            String agentPort = engine.getAgentPort();
            String adminPort = engine.getAdminPort();

            result.put("eeSSLPort", eeSSLPort != null ? eeSSLPort : "");
            result.put("eeNonSSLPort", eeNonSSLPort != null ? eeNonSSLPort : "");
            result.put("agentPort", agentPort != null ? agentPort : "");
            result.put("adminPort", adminPort != null ? adminPort : "");

            // Auth managers
            AuthSubsystem authSubsystem = engine.getAuthSubsystem();
            ArrayNode authMgrsArray = mapper.createArrayNode();
            if (authSubsystem != null) {
                Enumeration<AuthMgrPlugin> plugins = authSubsystem.getAuthManagerPlugins();
                while (plugins != null && plugins.hasMoreElements()) {
                    AuthMgrPlugin plugin = plugins.nextElement();
                    ObjectNode pluginNode = mapper.createObjectNode();
                    pluginNode.put("id", plugin.getId());
                    pluginNode.put("className", plugin.getClassPath());
                    authMgrsArray.add(pluginNode);
                }
            }
            result.set("authManagers", authMgrsArray);

        } catch (Exception e) {
            logger.error("DynamicVariablesResourceBase: Error: {}", e.getMessage(), e);
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
