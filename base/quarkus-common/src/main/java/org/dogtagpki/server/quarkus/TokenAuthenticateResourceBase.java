//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.quarkus;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Node;

import com.netscape.certsrv.base.SecurityDomainSessionTable;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmsutil.xml.XMLObject;

/**
 * Abstract base JAX-RS resource replacing the legacy TokenAuthenticate CMSServlet.
 * Validates a security domain session token.
 * Each subsystem extends this with a concrete @Path annotation.
 */
public abstract class TokenAuthenticateResourceBase {

    private static final Logger logger = LoggerFactory.getLogger(TokenAuthenticateResourceBase.class);
    private static final String SUCCESS = "0";

    protected abstract CMSEngine getEngine();

    @GET
    @Produces(MediaType.APPLICATION_XML)
    public Response tokenAuthenticate(
            @QueryParam("sessionID") String sessionId,
            @QueryParam("hostname") String givenHost) {

        logger.debug("TokenAuthenticateResourceBase: sessionId={}, hostname={}", sessionId, givenHost);

        CMSEngine engine = getEngine();
        EngineConfig config = engine.getConfig();

        try {
            boolean checkIP = config.getBoolean("securitydomain.checkIP", false);
            SecurityDomainSessionTable table = engine.getSecurityDomainSessionTable();

            if (table == null) {
                logger.error("TokenAuthenticateResourceBase: session table is null");
                return errorResponse("Error: session table is null");
            }

            if (!table.sessionExists(sessionId)) {
                logger.error("TokenAuthenticateResourceBase: session not found");
                return errorResponse("Error: Failed Authentication");
            }

            if (checkIP) {
                String hostname = table.getIP(sessionId);
                if (!hostname.equals(givenHost)) {
                    logger.error("TokenAuthenticateResourceBase: hostname mismatch: {} vs {}", hostname, givenHost);
                    return errorResponse("Error: Failed Authentication");
                }
            }

            String uid = table.getUID(sessionId);
            String gid = table.getGroup(sessionId);

            XMLObject xmlObj = new XMLObject();
            Node root = xmlObj.createRoot("XMLResponse");
            xmlObj.addItemToContainer(root, "Status", SUCCESS);
            xmlObj.addItemToContainer(root, "uid", uid);
            xmlObj.addItemToContainer(root, "gid", gid);

            return Response.ok(new String(xmlObj.toByteArray()), MediaType.APPLICATION_XML).build();

        } catch (Exception e) {
            logger.warn("TokenAuthenticateResourceBase: Error", e);
            return errorResponse("Error: " + e.getMessage());
        }
    }

    private Response errorResponse(String message) {
        try {
            XMLObject xmlObj = new XMLObject();
            Node root = xmlObj.createRoot("XMLResponse");
            xmlObj.addItemToContainer(root, "Status", "1");
            xmlObj.addItemToContainer(root, "Error", message);
            return Response.ok(new String(xmlObj.toByteArray()), MediaType.APPLICATION_XML).build();
        } catch (Exception e) {
            return Response.serverError().entity(message).build();
        }
    }
}
