//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.quarkus;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;

/**
 * Base JAX-RS resource replacing the legacy MainPageServlet CMSServlet.
 * Returns subsystem configuration information.
 */
public abstract class MainPageResourceBase {

    private static final Logger logger = LoggerFactory.getLogger(MainPageResourceBase.class);

    protected abstract CMSEngine getEngine();

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getMainPage() {

        logger.debug("MainPageResourceBase: Getting main page info");

        CMSEngine engine = getEngine();

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode result = mapper.createObjectNode();

        try {
            EngineConfig config = engine.getConfig();
            result.put("Status", "0");
            result.put("subsystemName", engine.getName());
            result.put("instanceId", engine.getID());

            String machineName = config.getHostname();
            result.put("machineName", machineName != null ? machineName : "");

        } catch (Exception e) {
            logger.error("MainPageResourceBase: Error: {}", e.getMessage(), e);
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
