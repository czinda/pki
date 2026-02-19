//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.quarkus;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cmscore.apps.CMS;

/**
 * JAX-RS resource replacing the legacy TPSPhoneHome servlet.
 * Returns phoneHome.xml configuration to TPS clients.
 *
 * The phoneHome.xml file is read from the TPS configuration directory
 * at {@code <instanceDir>/conf/tps/phoneHome.xml}.
 *
 * Legacy URL: /phoneHome
 */
@Path("phoneHome")
public class TPSPhoneHomeResource {

    private static final Logger logger = LoggerFactory.getLogger(TPSPhoneHomeResource.class);

    private static final String PHONE_HOME_FILE = "phoneHome.xml";

    @Inject
    TPSEngineQuarkus engineQuarkus;

    @GET
    @Produces(MediaType.APPLICATION_XML)
    public Response getPhoneHome() {

        logger.debug("TPSPhoneHomeResource entering.");

        try {
            String instanceDir = CMS.getInstanceDir();
            String confPath = instanceDir + File.separator + "conf"
                    + File.separator + "tps"
                    + File.separator + PHONE_HOME_FILE;

            logger.debug("TPSPhoneHomeResource: confPath: {}", confPath);

            byte[] data = Files.readAllBytes(Paths.get(confPath));

            logger.debug("TPSPhoneHomeResource: read {} bytes", data.length);

            return Response.ok(data, MediaType.APPLICATION_XML).build();

        } catch (IOException e) {
            logger.error("TPSPhoneHomeResource: {}", e.getMessage(), e);
            return Response.serverError()
                    .entity("Error reading phoneHome.xml: " + e.getMessage())
                    .build();
        }
    }
}
