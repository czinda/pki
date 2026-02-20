//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.io.ByteArrayOutputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.x509.CertificateChain;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.ca.CertificateAuthority;

/**
 * JAX-RS resource replacing the legacy GetCAChain CMSServlet.
 * Returns the CA certificate chain as binary (PKCS7 or DER).
 *
 * Legacy URL: /ee/ca/getCAChain
 */
@Path("ee/ca/getCAChain")
public class CAGetCAChainResource {

    private static final Logger logger = LoggerFactory.getLogger(CAGetCAChainResource.class);

    @Inject
    CAEngineQuarkus engineQuarkus;

    @GET
    public Response getCAChain(
            @QueryParam("op") String op,
            @QueryParam("mimeType") String mimeType,
            @Context HttpHeaders headers) throws Exception {

        logger.debug("CAGetCAChainResource.getCAChain(): op={}", op);

        if (op == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Missing 'op' parameter")
                    .build();
        }

        CAEngine engine = engineQuarkus.getEngine();
        CertificateAuthority ca = engine.getCA();

        if (op.startsWith("download")) {
            return downloadChain(op, mimeType, ca, headers);
        }

        return Response.status(Response.Status.BAD_REQUEST)
                .entity("Invalid operation: " + op)
                .build();
    }

    private Response downloadChain(
            String op,
            String mimeType,
            CertificateAuthority ca,
            HttpHeaders headers) throws Exception {

        byte[] bytes;

        // Check if client is MSIE (for backward compatibility)
        String userAgent = headers.getHeaderString("User-Agent");
        boolean isMSIE = userAgent != null && userAgent.contains("MSIE");

        if (isMSIE && (op.equals("download") || op.equals("downloadBIN"))) {
            // IE doesn't want PKCS7, return root CA cert only
            X509Certificate[] caCerts = ca.getCACertChain().getChain();
            try {
                bytes = caCerts[0].getEncoded();
            } catch (CertificateEncodingException e) {
                logger.error("CAGetCAChainResource: Error encoding CA cert", e);
                return Response.serverError().entity("Error encoding CA certificate").build();
            }
        } else {
            CertificateChain certChain = ca.getCACertChain();
            if (certChain == null) {
                return Response.serverError().entity("CA chain is empty").build();
            }

            ByteArrayOutputStream encoded = new ByteArrayOutputStream();
            certChain.encode(encoded, false);
            bytes = encoded.toByteArray();
        }

        if (mimeType == null || op.equals("downloadBIN")) {
            mimeType = "application/octet-stream";
        }

        Response.ResponseBuilder builder = Response.ok(bytes, mimeType);

        if (op.equals("downloadBIN")) {
            String filename = isMSIE ? "ca.cer" : "ca.p7c";
            builder.header("Content-Disposition", "attachment; filename=" + filename);
        }

        return builder.build();
    }
}
