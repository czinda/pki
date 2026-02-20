//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.quarkus;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmsutil.json.JSONObject;

/**
 * Abstract base JAX-RS resource replacing the legacy PortsServlet CMSServlet.
 * Returns port information (HTTP or HTTPS) based on the "secure" query parameter.
 * Each subsystem extends this with a concrete @Path annotation.
 *
 * Returns JSON: {"Response": {"Status": "0", "Port": "..."}}
 */
public abstract class PortsResourceBase {

    private static final Logger logger = LoggerFactory.getLogger(PortsResourceBase.class);
    private static final String SUCCESS = "0";

    protected abstract CMSEngine getEngine();

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getPorts(@QueryParam("secure") String secure) {

        logger.debug("PortsResourceBase: secure={}", secure);

        try {
            CMSEngine engine = getEngine();
            String port;

            if ("true".equals(secure)) {
                port = engine.getEESSLPort();
            } else {
                port = engine.getEENonSSLPort();
            }

            JSONObject jsonObj = new JSONObject();
            ObjectNode responseNode = jsonObj.getMapper().createObjectNode();
            responseNode.put("Status", SUCCESS);
            responseNode.put("Port", port);
            jsonObj.getRootNode().set("Response", responseNode);

            return Response.ok(new String(jsonObj.toByteArray()), MediaType.APPLICATION_JSON).build();

        } catch (Exception e) {
            logger.warn("PortsResourceBase: Failed to get port info", e);
            return Response.serverError()
                    .entity("{\"Error\":\"" + e.getMessage() + "\"}")
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }
    }
}
