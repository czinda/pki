//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.quarkus;

import java.util.Locale;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Node;

import com.netscape.certsrv.system.InstallToken;
import com.netscape.cms.servlet.csadmin.SecurityDomainProcessor;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmsutil.xml.XMLObject;

/**
 * Abstract base JAX-RS resource replacing the legacy GetCookie CMSServlet.
 * Issues an install token (cookie) for subsystem deployment.
 * Used by pkispawn to obtain security domain install tokens.
 *
 * The original servlet renders HTML templates; the Quarkus version
 * returns XML with the session ID for programmatic consumption.
 *
 * Each subsystem extends this with a concrete @Path annotation.
 */
public abstract class GetCookieResourceBase {

    private static final Logger logger = LoggerFactory.getLogger(GetCookieResourceBase.class);

    protected abstract CMSEngine getEngine();

    @GET
    @Produces(MediaType.APPLICATION_XML)
    public Response getCookie(
            @QueryParam("url") String url,
            @QueryParam("subsystem") String subsystem,
            @QueryParam("uid") String uid) {

        logger.info("GetCookieResourceBase: url={}, subsystem={}, uid={}", url, subsystem, uid);

        if (url == null || url.isEmpty()) {
            return errorResponse("Missing required parameter: url");
        }

        CMSEngine engine = getEngine();

        try {
            java.net.URL u = new java.net.URL(java.net.URLDecoder.decode(url, "UTF-8"));
            String addr = u.getHost();

            SecurityDomainProcessor processor = new SecurityDomainProcessor(Locale.getDefault());
            processor.setCMSEngine(engine);
            processor.init();

            InstallToken installToken = processor.getInstallToken(uid, addr, subsystem);
            String cookie = installToken.getToken();
            logger.debug("GetCookieResourceBase: Cookie generated");

            XMLObject xmlObj = new XMLObject();
            Node root = xmlObj.createRoot("XMLResponse");
            xmlObj.addItemToContainer(root, "Status", "0");
            xmlObj.addItemToContainer(root, "Cookie", cookie);
            byte[] cb = xmlObj.toByteArray();

            return Response.ok(new String(cb), MediaType.APPLICATION_XML).build();

        } catch (Exception e) {
            logger.warn("GetCookieResourceBase: {}", e.getMessage(), e);
            return errorResponse("Error: " + e.getMessage());
        }
    }

    private Response errorResponse(String message) {
        try {
            XMLObject xmlObj = new XMLObject();
            Node root = xmlObj.createRoot("XMLResponse");
            xmlObj.addItemToContainer(root, "Status", "2");
            xmlObj.addItemToContainer(root, "Error", message);
            byte[] cb = xmlObj.toByteArray();
            return Response.serverError()
                    .type(MediaType.APPLICATION_XML)
                    .entity(new String(cb))
                    .build();
        } catch (Exception e) {
            return Response.serverError().build();
        }
    }
}
