//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.quarkus;

import java.security.cert.X509Certificate;
import java.util.Enumeration;

import jakarta.ws.rs.POST;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.ConfigRoleEvent;
import com.netscape.certsrv.usrgrp.CertUserLocator;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmscore.usrgrp.ExactMatchCertUserLocator;
import com.netscape.cmscore.usrgrp.Group;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmscore.usrgrp.User;
import com.netscape.cmsutil.json.JSONObject;

/**
 * Abstract base JAX-RS resource replacing the legacy RegisterUser CMSServlet.
 * Creates a user and adds their certificate, then adds user to an admin group.
 * Used during subsystem deployment (pkispawn) for inter-subsystem registration.
 *
 * Each subsystem extends this with a concrete @Path annotation and group name.
 */
public abstract class RegisterUserResourceBase {

    private static final Logger logger = LoggerFactory.getLogger(RegisterUserResourceBase.class);
    private static final String SUCCESS = "0";

    protected abstract CMSEngine getEngine();

    protected abstract String getGroupName();

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response registerUser(
            @QueryParam("uid") String uid,
            @QueryParam("name") String name,
            @QueryParam("certificate") String certsString) {

        logger.info("RegisterUserResourceBase: uid={}, name={}", uid, name);

        CMSEngine engine = getEngine();
        Auditor auditor = engine.getAuditor();
        UGSubsystem ugsys = engine.getUGSubsystem();
        String groupName = getGroupName();

        String auditParams = "Scope;;users+Operation;;OP_ADD+source;;RegisterUser" +
                "+Resource;;" + uid +
                "+fullname;;" + name +
                "+state;;1+userType;;<null>+email;;<null>+password;;<null>+phone;;<null>";

        User user = null;
        boolean foundByCert = false;
        X509CertImpl cert = null;
        X509Certificate[] certs = new X509Certificate[1];

        try {
            // Parse the certificate
            byte[] bCert = Utils.base64decode(certsString);
            cert = new X509CertImpl(bCert);
            certs[0] = cert;

            // Try to find user by cert
            CertUserLocator cul = new ExactMatchCertUserLocator();
            cul.setCMSEngine(engine);
            com.netscape.certsrv.usrgrp.Certificates c =
                    new com.netscape.certsrv.usrgrp.Certificates(certs);
            user = cul.locateUser(c);
        } catch (Exception e) {
            logger.warn("RegisterUserResourceBase: Unable to find user by cert: {}", e.getMessage());
        }

        if (user == null) {
            try {
                user = ugsys.getUser(uid);
            } catch (Exception e) {
                logger.warn("RegisterUserResourceBase: Unable to find user {}", uid);
            }
        } else {
            foundByCert = true;
        }

        try {
            if (user == null) {
                logger.info("RegisterUserResourceBase: Creating user {}", uid);
                user = ugsys.createUser(uid);
                user.setFullName(name);
                user.setState("1");
                user.setUserType("");
                user.setEmail("");
                user.setPhone("");
                user.setPassword("");
                ugsys.addUser(user);

                auditor.log(new ConfigRoleEvent(null, ILogger.SUCCESS, auditParams));
            }

            user.setX509Certificates(certs);

            if (!foundByCert) {
                logger.info("RegisterUserResourceBase: Adding user certificate");
                ugsys.addUserCert(user.getUserID(), cert);
                auditor.log(new ConfigRoleEvent(null, ILogger.SUCCESS,
                        "Scope;;certs+Operation;;OP_ADD+source;;RegisterUser+Resource;;" + uid));
            }

        } catch (Exception e) {
            logger.error("RegisterUserResourceBase: Unable to create user: {}", e.getMessage(), e);
            auditor.log(new ConfigRoleEvent(null, ILogger.FAILURE, auditParams));
            return errorResponse("Error: Certificate malformed");
        }

        // Add user to group
        try {
            Enumeration<Group> groups = ugsys.findGroups(groupName);
            Group group = groups.nextElement();

            if (!group.isMember(user.getUserID())) {
                group.addMemberName(user.getUserID());
                ugsys.modifyGroup(group);
                auditor.log(new ConfigRoleEvent(null, ILogger.SUCCESS,
                        "Scope;;groups+Operation;;OP_MODIFY+source;;RegisterUser+Resource;;" + groupName));
            }
        } catch (Exception e) {
            logger.warn("RegisterUserResourceBase: Unable to add user to group {}: {}", groupName, e.getMessage());
        }

        try {
            JSONObject jsonObj = new JSONObject();
            ObjectNode responseNode = jsonObj.getMapper().createObjectNode();
            responseNode.put("Status", SUCCESS);
            jsonObj.getRootNode().set("Response", responseNode);
            return Response.ok(new String(jsonObj.toByteArray()), MediaType.APPLICATION_JSON).build();
        } catch (Exception e) {
            logger.warn("RegisterUserResourceBase: Failed to send output", e);
            return Response.serverError().build();
        }
    }

    private Response errorResponse(String message) {
        return Response.serverError()
                .type(MediaType.APPLICATION_JSON)
                .entity("{\"Error\":\"" + message + "\"}")
                .build();
    }
}
