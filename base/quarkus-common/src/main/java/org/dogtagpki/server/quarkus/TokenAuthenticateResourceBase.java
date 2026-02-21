//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.quarkus;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.SecurityDomainSessionTable;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;

/**
 * Abstract base JAX-RS resource replacing the legacy TokenAuthenticate CMSServlet.
 * Validates a security domain session token.
 * Each subsystem extends this with a concrete @Path annotation.
 *
 * Supports both GET (query params) and POST (form params) to match both
 * the legacy EE servlet and the admin servlet interfaces.
 */
public abstract class TokenAuthenticateResourceBase {

    private static final Logger logger = LoggerFactory.getLogger(TokenAuthenticateResourceBase.class);

    protected abstract CMSEngine getEngine();

    @GET
    @Produces(MediaType.APPLICATION_XML)
    public Response tokenAuthenticateGet(
            @QueryParam("sessionID") String sessionId,
            @QueryParam("hostname") String givenHost) {
        return doTokenAuthenticate(sessionId, givenHost);
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_XML)
    public Response tokenAuthenticatePost(
            @FormParam("sessionID") String sessionId,
            @FormParam("hostname") String givenHost) {
        return doTokenAuthenticate(sessionId, givenHost);
    }

    private Response doTokenAuthenticate(String sessionId, String givenHost) {

        logger.debug("TokenAuthenticateResourceBase: sessionId={}, hostname={}", sessionId, givenHost);

        CMSEngine engine = getEngine();
        EngineConfig config = engine.getConfig();

        try {
            boolean checkIP = config.getBoolean("securitydomain.checkIP", false);
            SecurityDomainSessionTable table = engine.getSecurityDomainSessionTable();

            if (table == null) {
                logger.error("TokenAuthenticateResourceBase: session table is null");
                return xmlResponse("1", null, null, "Error: session table is null");
            }

            if (!table.sessionExists(sessionId)) {
                logger.error("TokenAuthenticateResourceBase: session not found");
                return xmlResponse("1", null, null, "Error: Failed Authentication");
            }

            if (checkIP) {
                String hostname = table.getIP(sessionId);
                if (!hostname.equals(givenHost)) {
                    logger.error("TokenAuthenticateResourceBase: hostname mismatch: {} vs {}", hostname, givenHost);
                    return xmlResponse("1", null, null, "Error: Failed Authentication");
                }
            }

            String uid = table.getUID(sessionId);
            String gid = table.getGroup(sessionId);

            return xmlResponse("0", uid, gid, null);

        } catch (Exception e) {
            logger.warn("TokenAuthenticateResourceBase: Error", e);
            return xmlResponse("1", null, null, "Error: " + e.getMessage());
        }
    }

    private Response xmlResponse(String status, String uid, String gid, String error) {
        StringBuilder xml = new StringBuilder();
        xml.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        xml.append("<XMLResponse>");
        xml.append("<Status>").append(status).append("</Status>");
        if (uid != null) {
            xml.append("<uid>").append(escapeXml(uid)).append("</uid>");
        }
        if (gid != null) {
            xml.append("<gid>").append(escapeXml(gid)).append("</gid>");
        }
        if (error != null) {
            xml.append("<Error>").append(escapeXml(error)).append("</Error>");
        }
        xml.append("</XMLResponse>");
        return Response.ok(xml.toString(), MediaType.APPLICATION_XML).build();
    }

    private static String escapeXml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&apos;");
    }
}
