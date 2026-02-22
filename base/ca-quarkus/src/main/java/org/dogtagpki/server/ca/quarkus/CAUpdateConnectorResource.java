//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.util.Locale;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.certsrv.base.ConflictingOperationException;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.ConfigRoleEvent;
import com.netscape.certsrv.system.KRAConnectorInfo;
import com.netscape.cms.servlet.admin.KRAConnectorProcessor;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmscore.usrgrp.Group;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmscore.usrgrp.User;
import com.netscape.cmsutil.json.JSONObject;

/**
 * JAX-RS resource replacing the legacy UpdateConnector CMSServlet.
 * Creates a KRA connector in CA and creates a subsystem user for KRA.
 * Used during KRA deployment to register with the CA.
 * Legacy URL: /admin/ca/updateConnector
 */
@Path("admin/ca/updateConnector")
public class CAUpdateConnectorResource {

    private static final Logger logger = LoggerFactory.getLogger(CAUpdateConnectorResource.class);
    private static final String SUCCESS = "0";
    private static final String FAILED = "1";

    @Inject
    CAEngineQuarkus engineQuarkus;

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response updateConnector(
            @FormParam("ca.connector.KRA.host") String host,
            @FormParam("ca.connector.KRA.port") String port,
            @FormParam("ca.connector.KRA.timeout") String timeout,
            @FormParam("ca.connector.KRA.subsystemCert") String subsystemCert,
            @FormParam("ca.connector.KRA.transportCert") String transportCert,
            @FormParam("ca.connector.KRA.transportCertNickname") String transportCertNickname,
            @FormParam("ca.connector.KRA.uri") String uri,
            @FormParam("ca.connector.KRA.local") String local,
            @FormParam("ca.connector.KRA.enable") String enable) {

        logger.info("CAUpdateConnectorResource: Updating KRA connector");

        CAEngine engine = engineQuarkus.getEngine();
        Auditor auditor = engine.getAuditor();

        KRAConnectorInfo info = new KRAConnectorInfo();
        info.setHost(host);
        info.setPort(port);
        info.setTimeout(timeout);
        info.setSubsystemCert(subsystemCert);
        info.setTransportCert(transportCert);
        info.setTransportCertNickname(transportCertNickname);
        info.setUri(uri);
        info.setLocal(local);
        info.setEnable(enable);

        String url = "https://" + host + ":" + port;
        logger.info("CAUpdateConnectorResource: Adding KRA connector for {}", url);

        KRAConnectorProcessor processor = new KRAConnectorProcessor(Locale.getDefault());
        processor.setCMSEngine(engine);

        try {
            processor.init();
            processor.addConnector(info);
        } catch (Exception e) {
            String message = "Unable to add KRA connector for " + url + ": " + e.getMessage();
            logger.error("CAUpdateConnectorResource: {}", message, e);
            return sendResponse(FAILED, message);
        }

        // Create subsystem user for KRA
        UGSubsystem ugSubsystem = engine.getUGSubsystem();
        String uid = "KRA-" + host + "-" + port;
        String fullName = "KRA " + host + " " + port;
        logger.info("CAUpdateConnectorResource: Adding {} user", uid);

        String auditParams = "Scope;;users+Operation;;OP_ADD+source;;UpdateConnector" +
                "+Resource;;" + uid +
                "+fullname;;" + fullName +
                "+state;;1+userType;;agentType+email;;<null>+password;;<null>+phone;;<null>";

        try {
            User user = ugSubsystem.createUser(uid);
            user.setFullName(fullName);
            user.setEmail("");
            user.setPassword("");
            user.setUserType("agentType");
            user.setState("1");
            user.setPhone("");
            ugSubsystem.addUser(user);
            auditor.log(new ConfigRoleEvent(null, ILogger.SUCCESS, auditParams));
        } catch (ConflictingOperationException e) {
            logger.info("CAUpdateConnectorResource: User {} already exists", uid);
        } catch (Exception e) {
            String message = "Unable to add " + uid + " user: " + e.getMessage();
            logger.error("CAUpdateConnectorResource: {}", message, e);
            auditor.log(new ConfigRoleEvent(null, ILogger.FAILURE, auditParams));
            return sendResponse(FAILED, message);
        }

        // Add certificate
        logger.info("CAUpdateConnectorResource: Adding cert for {} user", uid);
        auditParams = "Scope;;certs+Operation;;OP_ADD+source;;UpdateConnector+Resource;;" + uid;

        try {
            byte[] binCert = Utils.base64decode(subsystemCert);
            X509CertImpl certImpl = new X509CertImpl(binCert);
            ugSubsystem.addUserCert(uid, certImpl);
            auditor.log(new ConfigRoleEvent(null, ILogger.SUCCESS, auditParams));
        } catch (ConflictingOperationException e) {
            logger.info("CAUpdateConnectorResource: Certificate for {} already exists", uid);
        } catch (Exception e) {
            String message = "Unable to add cert for " + uid + " user: " + e.getMessage();
            logger.error("CAUpdateConnectorResource: {}", message, e);
            auditor.log(new ConfigRoleEvent(null, ILogger.FAILURE, auditParams));
            return sendResponse(FAILED, message);
        }

        // Add user to Subsystem Group
        String groupName = "Subsystem Group";
        logger.info("CAUpdateConnectorResource: Adding {} user into {}", uid, groupName);
        auditParams = "Scope;;groups+Operation;;OP_MODIFY+source;;UpdateConnector+Resource;;" + groupName;

        try {
            Group group = ugSubsystem.getGroupFromName(groupName);
            if (!group.isMember(uid)) {
                group.addMemberName(uid);
                ugSubsystem.modifyGroup(group);
                auditor.log(new ConfigRoleEvent(null, ILogger.SUCCESS, auditParams));
            }
        } catch (Exception e) {
            String message = "Unable to add " + uid + " into " + groupName + ": " + e.getMessage();
            logger.error("CAUpdateConnectorResource: {}", message, e);
            auditor.log(new ConfigRoleEvent(null, ILogger.FAILURE, auditParams));
            return sendResponse(FAILED, message);
        }

        return sendResponse(SUCCESS, null);
    }

    private Response sendResponse(String status, String error) {
        try {
            JSONObject jsonObj = new JSONObject();
            ObjectNode responseNode = jsonObj.getMapper().createObjectNode();
            responseNode.put("Status", status);
            if (error != null) {
                responseNode.put("Error", error);
            }
            jsonObj.getRootNode().set("Response", responseNode);
            return Response.ok(new String(jsonObj.toByteArray()), MediaType.APPLICATION_JSON).build();
        } catch (Exception e) {
            logger.error("CAUpdateConnectorResource: Failed to send output: {}", e.getMessage(), e);
            return Response.serverError().build();
        }
    }
}
