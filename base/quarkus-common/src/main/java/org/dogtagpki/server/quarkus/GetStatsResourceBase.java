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

/**
 * Base JAX-RS resource replacing the legacy GetStats CMSServlet.
 * Returns server statistics.
 */
public abstract class GetStatsResourceBase {

    private static final Logger logger = LoggerFactory.getLogger(GetStatsResourceBase.class);

    protected abstract CMSEngine getEngine();

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getStats() {

        logger.debug("GetStatsResourceBase: Getting stats");

        CMSEngine engine = getEngine();

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode result = mapper.createObjectNode();

        try {
            result.put("Status", "0");
            result.put("serverStartTime", engine.getStartupTime());

            Runtime runtime = Runtime.getRuntime();
            result.put("freeMemory", runtime.freeMemory());
            result.put("totalMemory", runtime.totalMemory());
            result.put("maxMemory", runtime.maxMemory());
            result.put("availableProcessors", runtime.availableProcessors());

        } catch (Exception e) {
            logger.error("GetStatsResourceBase: Error: {}", e.getMessage(), e);
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
