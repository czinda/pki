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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * JAX-RS resource replacing the legacy GetEnableStatus CMSServlet.
 * Returns the enrollment enable/disable status.
 *
 * The original servlet was a stub that always returned "not yet implemented".
 * This resource preserves that behavior until the feature is fully implemented.
 *
 * Legacy URL: /ee/ca/getEnableStatus
 */
@Path("ee/ca/getEnableStatus")
public class CAGetEnableStatusResource {

    private static final Logger logger = LoggerFactory.getLogger(CAGetEnableStatusResource.class);

    @Inject
    CAEngineQuarkus engineQuarkus;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getEnableStatus() {

        logger.debug("CAGetEnableStatusResource: Getting enrollment enable status");

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode result = mapper.createObjectNode();

        // The legacy GetEnableStatus servlet was never implemented.
        // It always returned an error with "CMS_GW_NOT_YET_IMPLEMENTED".
        // Preserve that behavior here.
        result.put("Status", "1");
        result.put("Error", "Not yet implemented");

        return Response.ok(result.toString(), MediaType.APPLICATION_JSON).build();
    }
}
