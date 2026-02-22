//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.quarkus;

import java.util.Locale;

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

import com.netscape.cms.servlet.csadmin.SecurityDomainProcessor;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;

/**
 * Abstract base JAX-RS resource replacing the legacy UpdateDomainXML CMSServlet.
 * Updates the security domain (adds or removes subsystem hosts).
 * Used during pkispawn deployment for security domain registration.
 *
 * Supports both GET (query params) and POST (form params) to match both
 * the legacy admin servlet and agent servlet interfaces.
 *
 * Each subsystem extends this with a concrete @Path annotation.
 */
public abstract class UpdateDomainXMLResourceBase {

    private static final Logger logger = LoggerFactory.getLogger(UpdateDomainXMLResourceBase.class);

    protected abstract CMSEngine getEngine();

    @GET
    @Produces(MediaType.APPLICATION_XML)
    public Response updateDomainXMLGet(
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
        return doUpdateDomainXML(list, type, host, name, sport,
                agentsport, adminsport, eecaport, httpport,
                domainmgr, clone, operation);
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_XML)
    public Response updateDomainXMLPost(
            @FormParam("list") String list,
            @FormParam("type") String type,
            @FormParam("host") String host,
            @FormParam("name") String name,
            @FormParam("sport") String sport,
            @FormParam("agentsport") String agentsport,
            @FormParam("adminsport") String adminsport,
            @FormParam("eeclientauthsport") String eecaport,
            @FormParam("httpport") String httpport,
            @FormParam("dm") String domainmgr,
            @FormParam("clone") String clone,
            @FormParam("operation") String operation) {
        return doUpdateDomainXML(list, type, host, name, sport,
                agentsport, adminsport, eecaport, httpport,
                domainmgr, clone, operation);
    }

    private Response doUpdateDomainXML(
            String list, String type, String host, String name,
            String sport, String agentsport, String adminsport,
            String eecaport, String httpport, String domainmgr,
            String clone, String operation) {

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

        return xmlResponse(status, null);
    }

    private Response errorResponse(String message) {
        return xmlResponse("1", message);
    }

    private Response xmlResponse(String status, String error) {
        StringBuilder xml = new StringBuilder();
        xml.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        xml.append("<XMLResponse>");
        xml.append("<Status>").append(escapeXml(status)).append("</Status>");
        if (error != null) {
            xml.append("<Error>").append(escapeXml(error)).append("</Error>");
        }
        xml.append("</XMLResponse>");

        if ("0".equals(status)) {
            return Response.ok(xml.toString(), MediaType.APPLICATION_XML).build();
        }
        return Response.serverError()
                .type(MediaType.APPLICATION_XML)
                .entity(xml.toString())
                .build();
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
