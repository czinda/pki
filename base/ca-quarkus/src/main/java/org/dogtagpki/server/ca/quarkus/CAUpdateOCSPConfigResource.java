//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.util.Enumeration;

import jakarta.inject.Inject;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CAEngineConfig;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.certsrv.base.ConflictingOperationException;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.ConfigRoleEvent;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmscore.usrgrp.Group;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmscore.usrgrp.User;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.json.JSONObject;

/**
 * JAX-RS resource replacing the legacy UpdateOCSPConfig CMSServlet.
 * Configures OCSP publishing in CA and creates a subsystem user for OCSP.
 * Used during OCSP deployment to register with the CA.
 * Legacy URL: /ee/ca/updateOCSPConfig
 */
@Path("ee/ca/updateOCSPConfig")
public class CAUpdateOCSPConfigResource {

    private static final Logger logger = LoggerFactory.getLogger(CAUpdateOCSPConfigResource.class);
    private static final String SUCCESS = "0";
    private static final String FAILED = "1";

    @Inject
    CAEngineQuarkus engineQuarkus;

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response updateOCSPConfig(
            @QueryParam("ocsp_host") String ocsphost,
            @QueryParam("ocsp_port") String ocspport,
            @QueryParam("subsystemCert") String subsystemCert) {

        logger.info("CAUpdateOCSPConfigResource: Updating OCSP configuration");

        CAEngine engine = engineQuarkus.getEngine();
        CAEngineConfig cs = engine.getConfig();
        Auditor auditor = engine.getAuditor();

        // Configure OCSP publisher
        String ocspname = ocsphost.replace('.', '-') + "-" + ocspport;
        String publisherPrefix = "ca.publish.publisher.instance.OCSPPublisher-" + ocspname;
        String rulePrefix = "ca.publish.rule.instance.ocsprule-" + ocspname;

        // Get CA subsystem cert nickname for client auth
        String nickname = "";
        try {
            nickname = cs.getString("ca.subsystem.nickname", "");
            String tokenname = cs.getString("ca.subsystem.tokenname", "");
            if (!CryptoUtil.isInternalToken(tokenname))
                nickname = tokenname + ":" + nickname;
        } catch (Exception e) {
            // ignore
        }

        String url = "https://" + ocsphost + ":" + ocspport;
        logger.info("CAUpdateOCSPConfigResource: Adding OCSP publisher for {}", url);

        try {
            cs.putString("ca.publish.enable", "true");
            cs.putString(publisherPrefix + ".host", ocsphost);
            cs.putString(publisherPrefix + ".port", ocspport);
            cs.putString(publisherPrefix + ".nickName", nickname);
            cs.putString(publisherPrefix + ".path", "/ocsp/agent/ocsp/addCRL");
            cs.putString(publisherPrefix + ".pluginName", "OCSPPublisher");
            cs.putString(publisherPrefix + ".enableClientAuth", "true");
            cs.putString(rulePrefix + ".enable", "true");
            cs.putString(rulePrefix + ".mapper", "NoMap");
            cs.putString(rulePrefix + ".pluginName", "Rule");
            cs.putString(rulePrefix + ".publisher", "OCSPPublisher-" + ocspname);
            cs.putString(rulePrefix + ".type", "crl");
            cs.commit(false);
        } catch (Exception e) {
            String message = "Unable to add OCSP publisher for " + url + ": " + e.getMessage();
            logger.error("CAUpdateOCSPConfigResource: {}", message, e);
            return sendResponse(FAILED, message);
        }

        // Create subsystem user for OCSP
        UGSubsystem ugSubsystem = engine.getUGSubsystem();
        String uid = "OCSP-" + ocsphost + "-" + ocspport;
        String fullName = "OCSP " + ocsphost + " " + ocspport;
        logger.info("CAUpdateOCSPConfigResource: Adding {} user", uid);

        String auditParams = "Scope;;users+Operation;;OP_ADD+source;;UpdateOCSPConfig" +
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
            logger.info("CAUpdateOCSPConfigResource: User {} already exists", uid);
        } catch (Exception e) {
            String message = "Unable to add " + uid + " user: " + e.getMessage();
            logger.error("CAUpdateOCSPConfigResource: {}", message, e);
            auditor.log(new ConfigRoleEvent(null, ILogger.FAILURE, auditParams));
            return sendResponse(FAILED, message);
        }

        // Add certificate
        logger.info("CAUpdateOCSPConfigResource: Adding cert for {} user", uid);
        auditParams = "Scope;;certs+Operation;;OP_ADD+source;;UpdateOCSPConfig+Resource;;" + uid +
                "+cert;;" + subsystemCert;

        try {
            byte[] binCert = Utils.base64decode(subsystemCert);
            X509CertImpl certImpl = new X509CertImpl(binCert);
            ugSubsystem.addUserCert(uid, certImpl);
            auditor.log(new ConfigRoleEvent(null, ILogger.SUCCESS, auditParams));
        } catch (ConflictingOperationException e) {
            logger.info("CAUpdateOCSPConfigResource: Certificate for {} already exists", uid);
        } catch (Exception e) {
            String message = "Unable to add cert for " + uid + " user: " + e.getMessage();
            logger.error("CAUpdateOCSPConfigResource: {}", message, e);
            auditor.log(new ConfigRoleEvent(null, ILogger.FAILURE, auditParams));
            return sendResponse(FAILED, message);
        }

        // Add user to Subsystem Group
        String groupName = "Subsystem Group";
        logger.info("CAUpdateOCSPConfigResource: Adding {} user into {}", uid, groupName);
        auditParams = "Scope;;groups+Operation;;OP_MODIFY+source;;UpdateOCSPConfig" +
                "+Resource;;" + groupName;

        try {
            Group group = ugSubsystem.getGroupFromName(groupName);

            auditParams += "+user;;";
            Enumeration<String> members = group.getMemberNames();
            while (members.hasMoreElements()) {
                auditParams += members.nextElement();
                if (members.hasMoreElements()) {
                    auditParams += ",";
                }
            }

            if (!group.isMember(uid)) {
                auditParams += "," + uid;
                group.addMemberName(uid);
                ugSubsystem.modifyGroup(group);
                auditor.log(new ConfigRoleEvent(null, ILogger.SUCCESS, auditParams));
            } else {
                logger.info("CAUpdateOCSPConfigResource: User {} already in {}", uid, groupName);
            }
        } catch (Exception e) {
            String message = "Unable to add " + uid + " into " + groupName + ": " + e.getMessage();
            logger.error("CAUpdateOCSPConfigResource: {}", message, e);
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
            logger.error("CAUpdateOCSPConfigResource: Failed to send output: {}", e.getMessage(), e);
            return Response.serverError().build();
        }
    }
}
