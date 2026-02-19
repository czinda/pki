//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.util.List;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.rest.base.FeatureServletBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.netscape.certsrv.system.Feature;

/**
 * JAX-RS resource for CA feature operations.
 * Replaces CAFeatureServlet.
 */
@Path("v2/config/features")
public class CAFeatureResource {

    private static final Logger logger = LoggerFactory.getLogger(CAFeatureResource.class);

    @Inject
    CAEngineQuarkus engineQuarkus;

    private FeatureServletBase createBase() {
        return new FeatureServletBase(engineQuarkus.getEngine());
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response listFeatures() throws Exception {
        logger.debug("CAFeatureResource.listFeatures()");
        List<Feature> features = createBase().listFeatures();
        ObjectMapper mapper = new ObjectMapper();
        return Response.ok(mapper.writeValueAsString(features)).build();
    }

    @GET
    @Path("{featureId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getFeature(@PathParam("featureId") String featureId) throws Exception {
        logger.debug("CAFeatureResource.getFeature(): featureId={}", featureId);
        Feature feature = createBase().getFeature(featureId);
        return Response.ok(feature.toJSON()).build();
    }
}
