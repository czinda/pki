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

import com.netscape.cms.servlet.csadmin.SecurityDomainProcessor;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmsutil.xml.XMLObject;

/**
 * Abstract base JAX-RS resource replacing the legacy UpdateDomainXML CMSServlet.
 * Updates the security domain (adds or removes subsystem hosts).
 * Used during pkispawn deployment for security domain registration.
 *
 * Each subsystem extends this with a concrete @Path annotation.
 */
public abstract class UpdateDomainXMLResourceBase {

    private static final Logger logger = LoggerFactory.getLogger(UpdateDomainXMLResourceBase.class);

    protected abstract CMSEngine getEngine();

    @GET
    @Produces(MediaType.APPLICATION_XML)
    public Response updateDomainXML(
            @QueryParam("list") String list,
            @QueryParam("type") String type,
            @QueryParam("host") String host,
            @QueryParam("name") String name,
            @QueryParam("sport") String sport,
            @QueryParam("agentsport") String agentsport,
            @QueryParam("adminsport") String adminsport,
            @QueryParam("eeclientauthsport") String eecaport,
            @QueryParam("httpport") String httpport,
            @QueryParam("dm") String domainmgr,
            @QueryParam("clone") String clone,
            @QueryParam("operation") String operation) {

        logger.info("UpdateDomainXMLResourceBase: Updating security domain");

        CMSEngine engine = getEngine();
        EngineConfig cs = engine.getConfig();

        // validate required parameters
        StringBuilder missing = new StringBuilder();
        if (host == null || host.isEmpty()) missing.append(" host");
        if (name == null || name.isEmpty()) missing.append(" name");
        if (sport == null || sport.isEmpty()) missing.append(" sport");
        if (type == null || type.isEmpty()) missing.append(" type");
        if (clone == null || clone.isEmpty()) clone = "false";

        if (missing.length() > 0) {
            logger.error("UpdateDomainXMLResourceBase: Missing required parameters:{}", missing);
            return errorResponse("Missing required parameters:" + missing);
        }

        try {
            LDAPConfig ldapConfig = cs.getInternalDBConfig();
            String basedn = ldapConfig.getBaseDN();
            logger.info("UpdateDomainXMLResourceBase: Base DN: {}", basedn);
        } catch (Exception e) {
            logger.warn("UpdateDomainXMLResourceBase: Unable to determine basedn: {}", e.getMessage());
        }

        String status;
        try {
            SecurityDomainProcessor processor = new SecurityDomainProcessor(Locale.getDefault());
            processor.setCMSEngine(engine);
            processor.init();

            if ("remove".equals(operation)) {
                status = processor.removeHost(name, type, host, sport);
            } else {
                status = processor.addHost(
                        name, type, host, sport, httpport,
                        eecaport, adminsport, agentsport,
                        domainmgr, clone);
            }
        } catch (Exception e) {
            logger.error("UpdateDomainXMLResourceBase: Failed to update domain: {}", e.getMessage(), e);
            return errorResponse("Failed to update domain: " + e.getMessage());
        }

        logger.info("UpdateDomainXMLResourceBase: Status: {}", status);

        try {
            XMLObject xmlObj = new XMLObject();
            Node root = xmlObj.createRoot("XMLResponse");
            xmlObj.addItemToContainer(root, "Status", status);
            byte[] cb = xmlObj.toByteArray();
            return Response.ok(new String(cb), MediaType.APPLICATION_XML).build();
        } catch (Exception e) {
            logger.warn("UpdateDomainXMLResourceBase: Failed to send output: {}", e.getMessage(), e);
            return Response.serverError().build();
        }
    }

    private Response errorResponse(String message) {
        try {
            XMLObject xmlObj = new XMLObject();
            Node root = xmlObj.createRoot("XMLResponse");
            xmlObj.addItemToContainer(root, "Status", "1");
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
