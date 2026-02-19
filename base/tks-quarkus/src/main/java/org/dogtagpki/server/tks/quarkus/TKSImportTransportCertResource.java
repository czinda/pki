//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tks.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.tks.TKSEngine;
import org.dogtagpki.server.tks.TKSEngineConfig;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.netscape.security.util.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.cmsutil.json.JSONObject;

/**
 * JAX-RS resource replacing the legacy ImportTransportCert CMSServlet.
 * Imports KRA's transport certificate into TKS.
 * Legacy URL: /admin/tks/importTransportCert
 */
@Path("admin/tks/importTransportCert")
public class TKSImportTransportCertResource {

    private static final Logger logger = LoggerFactory.getLogger(TKSImportTransportCertResource.class);
    private static final String SUCCESS = "0";

    @Inject
    TKSEngineQuarkus engineQuarkus;

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response importTransportCert(@QueryParam("certificate") String certsString) {

        logger.info("TKSImportTransportCertResource: Importing transport certificate");

        TKSEngine engine = engineQuarkus.getEngine();
        TKSEngineConfig cs = engine.getConfig();

        try {
            CryptoManager cm = CryptoManager.getInstance();
            logger.debug("TKSImportTransportCertResource: Importing certificate");
            org.mozilla.jss.crypto.X509Certificate cert =
                    cm.importCACertPackage(Utils.base64decode(certsString));
            String nickName = cert.getNickname();
            logger.debug("TKSImportTransportCertResource: nickname={}", nickName);
            cs.putString("tks.drm_transport_cert_nickname", nickName);
            cs.commit(false);

            JSONObject jsonObj = new JSONObject();
            ObjectNode responseNode = jsonObj.getMapper().createObjectNode();
            responseNode.put("Status", SUCCESS);
            jsonObj.getRootNode().set("Response", responseNode);
            return Response.ok(new String(jsonObj.toByteArray()), MediaType.APPLICATION_JSON).build();

        } catch (Exception e) {
            logger.warn("TKSImportTransportCertResource: {}", e.getMessage(), e);
            return Response.serverError()
                    .type(MediaType.APPLICATION_JSON)
                    .entity("{\"Error\":\"" + e.getMessage() + "\"}")
                    .build();
        }
    }
}
