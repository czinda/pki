//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.ca.CAEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmsutil.json.JSONObject;

/**
 * JAX-RS resource replacing the legacy GetStatus CMSServlet for CA.
 * Returns the subsystem status as JSON.
 *
 * Legacy URL: /admin/ca/getStatus
 */
@Path("admin/ca/getStatus")
public class CAGetStatusResource {

    private static final Logger logger = LoggerFactory.getLogger(CAGetStatusResource.class);

    @Inject
    CAEngineQuarkus engineQuarkus;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getStatus() {
        logger.debug("CAGetStatusResource.getStatus()");

        try {
            CAEngine engine = engineQuarkus.getEngine();
            EngineConfig config = engine.getConfig();

            int state = config.getState();
            String type = engine.getName();
            String status = engine.isReady() ? "running" : "starting";
            String version = getClass().getPackage().getImplementationVersion();

            JSONObject jsonObj = new JSONObject();
            ObjectNode responseNode = jsonObj.getMapper().createObjectNode();
            responseNode.put("State", String.valueOf(state));
            responseNode.put("Type", type);
            responseNode.put("Status", status);
            responseNode.put("Version", version);

            String productName = CMS.getProductName();
            if (productName != null && !productName.isEmpty()) {
                responseNode.put("ProductVersion", productName);
            }

            jsonObj.getRootNode().set("Response", responseNode);

            return Response.ok(new String(jsonObj.toByteArray()), MediaType.APPLICATION_JSON).build();

        } catch (Exception e) {
            logger.warn("CAGetStatusResource: Failed to get status", e);
            return Response.serverError().entity("{\"Error\":\"" + e.getMessage() + "\"}").build();
        }
    }
}
