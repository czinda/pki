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

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CAEngineConfig;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.X509Certificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.json.JSONObject;

/**
 * JAX-RS resource replacing the legacy GetSubsystemCert CMSServlet.
 * Returns the subsystem certificate as base64-encoded JSON.
 * Legacy URL: /admin/ca/getSubsystemCert
 */
@Path("admin/ca/getSubsystemCert")
public class CAGetSubsystemCertResource {

    private static final Logger logger = LoggerFactory.getLogger(CAGetSubsystemCertResource.class);
    private static final String SUCCESS = "0";

    @Inject
    CAEngineQuarkus engineQuarkus;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getSubsystemCert() {

        CAEngine engine = engineQuarkus.getEngine();
        CAEngineConfig cs = engine.getConfig();

        String nickname = "";
        try {
            nickname = cs.getString("ca.subsystem.nickname", "");
            String tokenname = cs.getString("ca.subsystem.tokenname", "");
            if (!CryptoUtil.isInternalToken(tokenname))
                nickname = tokenname + ":" + nickname;
        } catch (Exception e) {
            logger.warn("CAGetSubsystemCertResource: Unable to get nickname: {}", e.getMessage());
        }

        logger.debug("CAGetSubsystemCertResource: nickname={}", nickname);
        String certBase64 = "";
        try {
            CryptoManager cm = CryptoManager.getInstance();
            X509Certificate cert = cm.findCertByNickname(nickname);

            if (cert == null) {
                logger.warn("CAGetSubsystemCertResource: subsystem cert is null");
                return Response.serverError()
                        .type(MediaType.APPLICATION_JSON)
                        .entity("{\"Error\":\"Failed to get subsystem certificate.\"}")
                        .build();
            }

            byte[] bytes = cert.getEncoded();
            certBase64 = CryptoUtil.normalizeCertStr(CryptoUtil.base64Encode(bytes));
        } catch (Exception e) {
            logger.warn("CAGetSubsystemCertResource: {}", e.getMessage(), e);
        }

        try {
            JSONObject jsonObj = new JSONObject();
            ObjectNode responseNode = jsonObj.getMapper().createObjectNode();
            responseNode.put("Status", SUCCESS);
            responseNode.put("Cert", certBase64);
            jsonObj.getRootNode().set("Response", responseNode);
            return Response.ok(new String(jsonObj.toByteArray()), MediaType.APPLICATION_JSON).build();
        } catch (Exception e) {
            logger.warn("CAGetSubsystemCertResource: Failed to send output: {}", e.getMessage(), e);
            return Response.serverError().build();
        }
    }
}
