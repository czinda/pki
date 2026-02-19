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
import org.mozilla.jss.netscape.security.util.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.cmsutil.json.JSONObject;
import com.netscape.kra.KeyRecoveryAuthority;
import com.netscape.kra.TransportKeyUnit;

/**
 * JAX-RS resource replacing the legacy GetTransportCert CMSServlet.
 * Returns the KRA transport certificate as base64-encoded JSON.
 * Legacy URL: /admin/kra/getTransportCert
 */
@Path("admin/kra/getTransportCert")
public class KRAGetTransportCertResource {

    private static final Logger logger = LoggerFactory.getLogger(KRAGetTransportCertResource.class);
    private static final String SUCCESS = "0";

    @Inject
    KRAEngineQuarkus engineQuarkus;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getTransportCert() {

        KRAEngine engine = engineQuarkus.getEngine();
        KeyRecoveryAuthority kra = engine.getKRA();
        TransportKeyUnit tu = kra.getTransportKeyUnit();
        org.mozilla.jss.crypto.X509Certificate transportCert = tu.getCertificate();

        String mime64 = "";
        try {
            mime64 = Utils.base64encode(transportCert.getEncoded(), true);
            mime64 = org.mozilla.jss.netscape.security.util.Cert.normalizeCertStrAndReq(mime64);
        } catch (CertificateEncodingException e) {
            logger.warn("KRAGetTransportCertResource: Failed to encode certificate: {}", e.getMessage(), e);
        }

        try {
            JSONObject jsonObj = new JSONObject();
            ObjectNode responseNode = jsonObj.getMapper().createObjectNode();
            responseNode.put("Status", SUCCESS);
            responseNode.put("TransportCert", mime64);
            jsonObj.getRootNode().set("Response", responseNode);
            return Response.ok(new String(jsonObj.toByteArray()), MediaType.APPLICATION_JSON).build();
        } catch (Exception e) {
            logger.warn("KRAGetTransportCertResource: Failed to send output: {}", e.getMessage(), e);
            return Response.serverError().build();
        }
    }
}
