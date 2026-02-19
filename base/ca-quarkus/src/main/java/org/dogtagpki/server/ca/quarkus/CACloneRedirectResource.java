//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.net.URI;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CAEngineConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * JAX-RS resource replacing the legacy CloneRedirect CMSServlet.
 * Redirects requests to the master CA when this is a clone.
 * Legacy URL: /ee/ca/cloneRedirect
 */
@Path("ee/ca/cloneRedirect")
public class CACloneRedirectResource {

    private static final Logger logger = LoggerFactory.getLogger(CACloneRedirectResource.class);

    @Inject
    CAEngineQuarkus engineQuarkus;

    @GET
    public Response cloneRedirect() {
        logger.info("CACloneRedirectResource: Redirecting to master");

        CAEngine engine = engineQuarkus.getEngine();
        CAEngineConfig cs = engine.getConfig();

        try {
            String masterHost = cs.getString("master.ca.agent.host", "");
            String masterPort = cs.getString("master.ca.agent.port", "");

            if (!masterHost.isEmpty() && !masterPort.isEmpty()) {
                String redirectUrl = "https://" + masterHost + ":" + masterPort;
                return Response.temporaryRedirect(URI.create(redirectUrl)).build();
            }
        } catch (Exception e) {
            logger.error("CACloneRedirectResource: Error: {}", e.getMessage(), e);
        }

        return Response.status(Response.Status.NOT_FOUND)
                .entity("{\"Error\":\"No master CA configured\"}")
                .build();
    }
}
