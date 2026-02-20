//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

import java.security.cert.CertificateEncodingException;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.kra.KRAEngine;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.kra.KeyRecoveryAuthority;
import com.netscape.kra.TransportKeyUnit;

/**
 * JAX-RS resource replacing the legacy DisplayTransport CMSServlet.
 * Displays the KRA transport certificate used to wrap private key
 * archival requests.
 *
 * Legacy URL: /agent/kra/displayTransportCert
 */
@Path("agent/kra/displayTransportCert")
public class KRADisplayTransportResource {

    private static final Logger logger = LoggerFactory.getLogger(KRADisplayTransportResource.class);

    @Inject
    KRAEngineQuarkus engineQuarkus;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response displayTransportCert() {

        logger.debug("KRADisplayTransportResource.displayTransportCert()");

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode result = mapper.createObjectNode();

        try {
            KRAEngine engine = engineQuarkus.getEngine();
            KeyRecoveryAuthority kra = engine.getKRA();

            TransportKeyUnit tu = kra.getTransportKeyUnit();
            org.mozilla.jss.crypto.X509Certificate transportCert = tu.getCertificate();

            if (transportCert == null) {
                result.put("Status", "1");
                result.put("Error", "Transport certificate not available");
                return Response.status(Response.Status.NOT_FOUND)
                        .entity(result.toString())
                        .type(MediaType.APPLICATION_JSON)
                        .build();
            }

            String base64Cert = Utils.base64encode(transportCert.getEncoded(), true);
            String pemCert = Cert.HEADER + "\n" + base64Cert + Cert.FOOTER + "\n";

            result.put("Status", "0");
            result.put("transportCert", base64Cert.trim());
            result.put("transportCertPEM", pemCert);
            result.put("nickname", transportCert.getNickname());

            return Response.ok(result.toString(), MediaType.APPLICATION_JSON).build();

        } catch (CertificateEncodingException e) {
            logger.error("KRADisplayTransportResource: Failed to encode transport certificate: {}", e.getMessage(), e);
            result.put("Status", "1");
            result.put("Error", "Failed to encode transport certificate: " + e.getMessage());
            return Response.serverError()
                    .entity(result.toString())
                    .type(MediaType.APPLICATION_JSON)
                    .build();

        } catch (Exception e) {
            logger.error("KRADisplayTransportResource: Failed to get transport certificate: {}", e.getMessage(), e);
            result.put("Status", "1");
            result.put("Error", "Failed to get transport certificate: " + e.getMessage());
            return Response.serverError()
                    .entity(result.toString())
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }
    }
}
