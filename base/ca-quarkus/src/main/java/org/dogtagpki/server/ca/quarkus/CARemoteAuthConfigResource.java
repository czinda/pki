//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.util.Enumeration;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.authentication.AuthManager;
import org.dogtagpki.server.ca.CAEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.certsrv.authentication.AuthMgrPlugin;
import com.netscape.cmscore.authentication.AuthSubsystem;

/**
 * JAX-RS resource replacing the legacy RemoteAuthConfig CMSServlet.
 * Returns authentication manager configuration.
 * Legacy URL: /agent/ca/remoteAuthConfig
 */
@Path("agent/ca/remoteAuthConfig")
public class CARemoteAuthConfigResource {

    private static final Logger logger = LoggerFactory.getLogger(CARemoteAuthConfigResource.class);

    @Inject
    CAEngineQuarkus engineQuarkus;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getRemoteAuthConfig() {

        logger.debug("CARemoteAuthConfigResource: Getting auth config");

        CAEngine engine = engineQuarkus.getEngine();

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode result = mapper.createObjectNode();

        try {
            AuthSubsystem authSubsystem = engine.getAuthSubsystem();
            ArrayNode authMgrsArray = mapper.createArrayNode();

            Enumeration<AuthMgrPlugin> plugins = authSubsystem.getAuthManagerPlugins();
            while (plugins != null && plugins.hasMoreElements()) {
                AuthMgrPlugin plugin = plugins.nextElement();
                ObjectNode pluginNode = mapper.createObjectNode();
                pluginNode.put("id", plugin.getId());
                pluginNode.put("className", plugin.getClassPath());
                authMgrsArray.add(pluginNode);
            }

            Enumeration<AuthManager> instances = authSubsystem.getAuthManagers();
            ArrayNode instancesArray = mapper.createArrayNode();
            while (instances != null && instances.hasMoreElements()) {
                AuthManager mgr = instances.nextElement();
                ObjectNode mgrNode = mapper.createObjectNode();
                mgrNode.put("name", mgr.getName());
                instancesArray.add(mgrNode);
            }

            result.put("Status", "0");
            result.set("authManagerPlugins", authMgrsArray);
            result.set("authManagerInstances", instancesArray);

        } catch (Exception e) {
            logger.error("CARemoteAuthConfigResource: Error: {}", e.getMessage(), e);
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
