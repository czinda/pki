//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tks.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.tks.TKSEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmsutil.json.JSONObject;

/**
 * JAX-RS resource replacing the legacy GetStatus CMSServlet for TKS.
 *
 * Legacy URL: /admin/tks/getStatus
 */
@Path("admin/tks/getStatus")
public class TKSGetStatusResource {

    private static final Logger logger = LoggerFactory.getLogger(TKSGetStatusResource.class);

    @Inject
    TKSEngineQuarkus engineQuarkus;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getStatus() {
        logger.debug("TKSGetStatusResource.getStatus()");
        try {
            TKSEngine engine = engineQuarkus.getEngine();
            EngineConfig config = engine.getConfig();

            JSONObject jsonObj = new JSONObject();
            ObjectNode responseNode = jsonObj.getMapper().createObjectNode();
            responseNode.put("State", String.valueOf(config.getState()));
            responseNode.put("Type", engine.getName());
            responseNode.put("Status", engine.isReady() ? "running" : "starting");
            responseNode.put("Version", getClass().getPackage().getImplementationVersion());

            String productName = CMS.getProductName();
            if (productName != null && !productName.isEmpty()) {
                responseNode.put("ProductVersion", productName);
            }
            jsonObj.getRootNode().set("Response", responseNode);

            return Response.ok(new String(jsonObj.toByteArray()), MediaType.APPLICATION_JSON).build();
        } catch (Exception e) {
            logger.warn("TKSGetStatusResource: Failed to get status", e);
            return Response.serverError().entity("{\"Error\":\"" + e.getMessage() + "\"}").build();
        }
    }
}
