//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.io.ByteArrayOutputStream;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.CertificateChain;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.ca.CertificateAuthority;

/**
 * JAX-RS resource replacing the legacy GetCertChain CMSServlet.
 * Returns the CA certificate chain as base64-encoded JSON.
 *
 * Legacy URL: /ee/ca/getCertChain
 */
@Path("ee/ca/getCertChain")
public class CAGetCertChainResource {

    private static final Logger logger = LoggerFactory.getLogger(CAGetCertChainResource.class);

    @Inject
    CAEngineQuarkus engineQuarkus;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getCertChain() throws Exception {
        logger.debug("CAGetCertChainResource.getCertChain()");

        CAEngine engine = engineQuarkus.getEngine();
        CertificateAuthority ca = engine.getCA();
        CertificateChain certChain = ca.getCACertChain();

        if (certChain == null) {
            logger.warn("CAGetCertChainResource: certificate chain not available");
            return Response.serverError()
                    .type(MediaType.APPLICATION_JSON)
                    .entity("{\"Response\":{\"Status\":\"1\",\"Error\":\"Certificate chain not available\"}}")
                    .build();
        }

        ByteArrayOutputStream encoded = new ByteArrayOutputStream();
        certChain.encode(encoded);
        byte[] bytes = encoded.toByteArray();

        String chainBase64 = Utils.base64encode(bytes, true);
        // Normalize: remove whitespace, newlines, quotes
        chainBase64 = chainBase64.replaceAll("[\\n\\r\" ]", "");

        String json = "{\"Response\":{\"Status\":\"0\",\"ChainBase64\":\"" + chainBase64 + "\"}}";

        return Response.ok(json, MediaType.APPLICATION_JSON).build();
    }
}
