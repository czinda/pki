//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.quarkus;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmsutil.json.JSONObject;

/**
 * Abstract base for CheckIdentity servlet replacement.
 * Simply verifies that the caller is authenticated (via client cert).
 * Returns Status 0 on success.
 * Legacy URL pattern: /admin/{subsystem}/checkIdentity
 */
public abstract class CheckIdentityResourceBase {

    private static final Logger logger = LoggerFactory.getLogger(CheckIdentityResourceBase.class);
    private static final String SUCCESS = "0";

    protected abstract CMSEngine getEngine();

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response checkIdentity() {

        logger.info("CheckIdentityResourceBase: Checking identity");

        try {
            JSONObject jsonObj = new JSONObject();
            ObjectNode responseNode = jsonObj.getMapper().createObjectNode();
            responseNode.put("Status", SUCCESS);
            jsonObj.getRootNode().set("Response", responseNode);
            return Response.ok(new String(jsonObj.toByteArray()), MediaType.APPLICATION_JSON).build();
        } catch (Exception e) {
            logger.warn("CheckIdentityResourceBase: Failed to send output: {}", e.getMessage(), e);
            return Response.serverError().build();
        }
    }
}
