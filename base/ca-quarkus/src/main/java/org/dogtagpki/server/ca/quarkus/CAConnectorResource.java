//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.StreamCorruptedException;
import java.security.cert.X509Certificate;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;

import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.ca.CAEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.connector.IPKIMessage;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.AuditFormat;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.CertRequestProcessedEvent;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.realm.PKIPrincipalCore;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.connector.HttpPKIMessage;
import com.netscape.cmscore.connector.HttpRequestEncoder;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestQueue;
import com.netscape.cmscore.request.RequestRepository;

import io.quarkus.security.identity.SecurityIdentity;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;

/**
 * JAX-RS resource replacing the legacy ConnectorServlet for CA.
 * Handles inter-subsystem RPC (CA<->KRA, CA<->OCSP).
 *
 * Legacy URL: /agent/ca/connector (configured in web.xml)
 */
@Path("agent/ca/connector")
public class CAConnectorResource {

    private static final Logger logger = LoggerFactory.getLogger(CAConnectorResource.class);
    private static final String SIGNED_AUDIT_PROTECTION_METHOD_SSL = "ssl";

    @Inject
    CAEngineQuarkus engineQuarkus;

    @Inject
    SecurityIdentity securityIdentity;

    @Context
    SecurityContext securityContext;

    private final HttpRequestEncoder reqEncoder = new HttpRequestEncoder();

    @POST
    @Consumes(MediaType.WILDCARD)
    public Response processRequest(String encodedRequest) {
        logger.info("CAConnectorResource: Processing connector request");

        CAEngine engine = engineQuarkus.getEngine();
        Auditor auditor = engine.getAuditor();

        if (!engine.isInRunningState()) {
            logger.error("CAConnectorResource: Server is not ready");
            return Response.status(Response.Status.SERVICE_UNAVAILABLE).build();
        }

        if (encodedRequest == null || encodedRequest.isEmpty()) {
            logger.warn("CAConnectorResource: Missing request content");
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        // Get authenticated principal
        java.security.Principal principal = securityContext.getUserPrincipal();
        if (principal == null) {
            logger.warn("CAConnectorResource: Not authenticated");
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }

        String sourceUserId = principal.getName();
        String source = principal.getName(); // Using principal name as source ID

        // Extract auth token from security identity
        AuthToken token = null;
        PKIPrincipalCore pkiPrincipal = securityIdentity.getAttribute("pki.principal");
        if (pkiPrincipal != null) {
            token = (AuthToken) pkiPrincipal.getAuthToken();
            if (token != null) {
                sourceUserId = token.getInString("userid");
            }
        }

        String auditSubjectID = sourceUserId != null ? sourceUserId.trim() : ILogger.UNIDENTIFIED;

        try {
            // Decode the PKI message
            IPKIMessage msg = (IPKIMessage) reqEncoder.decode(encodedRequest);

            String auditRequestType = msg.getReqType();
            String auditRequesterID = msg.getReqId();

            if (auditRequestType != null) auditRequestType = auditRequestType.trim();
            else auditRequestType = ILogger.SIGNED_AUDIT_EMPTY_VALUE;
            if (auditRequesterID != null) auditRequesterID = auditRequesterID.trim();
            else auditRequesterID = ILogger.UNIDENTIFIED;

            // Process the request
            IPKIMessage replymsg = processRequest(
                    engine, auditor, source, sourceUserId, msg, token,
                    auditSubjectID, auditRequestType, auditRequesterID);

            // Encode reply
            String encodedReply = reqEncoder.encode(replymsg);

            return Response.ok(encodedReply, "text/html").build();

        } catch (Exception e) {
            logger.error("CAConnectorResource: Error processing request", e);
            return Response.serverError().build();
        }
    }

    private IPKIMessage processRequest(
            CAEngine engine,
            Auditor auditor,
            String source,
            String sourceUserId,
            IPKIMessage msg,
            AuthToken token,
            String auditSubjectID,
            String auditRequestType,
            String auditRequesterID) throws Exception {

        RequestRepository requestRepository = engine.getRequestRepository();
        RequestQueue queue = engine.getRequestQueue();
        String srcid = source + ":" + msg.getReqId();

        logger.debug("CAConnectorResource: srcid={}", srcid);

        // Check if request already exists
        RequestId thisreqid = requestRepository.findRequestBySourceId(srcid);

        if (thisreqid != null) {
            Request thisreq = requestRepository.readRequest(thisreqid);
            if (thisreq == null) {
                auditor.log(CMS.getLogMessage(
                        AuditEvent.INTER_BOUNDARY, auditSubjectID, ILogger.FAILURE,
                        SIGNED_AUDIT_PROTECTION_METHOD_SSL, auditRequestType, auditRequesterID));
                throw new Exception("Cannot find request " + thisreqid);
            }

            // Check for server-side keygen stage transition
            String sskStage = thisreq.getExtDataInString(Request.SSK_STAGE);
            if (sskStage != null && sskStage.equalsIgnoreCase(Request.SSK_STAGE_KEYGEN)) {
                logger.debug("CAConnectorResource: SSK stage={}", sskStage);
            } else {
                logger.debug("CAConnectorResource: Found existing request {} for {}", thisreqid, srcid);
                IPKIMessage replymsg = new HttpPKIMessage();
                replymsg.fromRequest(thisreq);

                auditor.log(CMS.getLogMessage(
                        AuditEvent.INTER_BOUNDARY, auditSubjectID, ILogger.SUCCESS,
                        SIGNED_AUDIT_PROTECTION_METHOD_SSL, auditRequestType, auditRequesterID));
                return replymsg;
            }
        }

        // Create new request
        Request thisreq = requestRepository.createRequest(msg.getReqType());
        logger.debug("CAConnectorResource: created requestId={}", thisreq.getRequestId());

        thisreq.setSourceId(srcid);
        msg.toRequest(thisreq);

        thisreq.setExtData("dbStatus", "NOT_UPDATED");
        thisreq.setExtData(Request.REQ_STATUS, "begin");

        // Handle server-side keygen
        String isSSKeygenStr = thisreq.getExtDataInString("isServerSideKeygen");
        if ("true".equalsIgnoreCase(isSSKeygenStr)) {
            String sskStage = thisreq.getExtDataInString(Request.SSK_STAGE);
            if (sskStage != null) {
                if (sskStage.equalsIgnoreCase(Request.SSK_STAGE_KEYGEN)) {
                    thisreq.setRequestType("asymkeyGenRequest");
                } else if (sskStage.equalsIgnoreCase(Request.SSK_STAGE_KEY_RETRIEVE)) {
                    thisreq.setRequestType("recovery");
                }
            }
        }

        if (token != null) {
            thisreq.setExtData(Request.AUTH_TOKEN, token);
        }

        String reqRealm = msg.getReqRealm();
        if (reqRealm != null && !reqRealm.isEmpty()) {
            thisreq.setRealm(reqRealm);
        }

        thisreq.setExtData(Request.REQUESTOR_TYPE, Request.REQUESTOR_RA);

        // Set session context
        SessionContext s = SessionContext.getContext();
        if (s.get(SessionContext.USER_ID) == null) {
            s.put(SessionContext.USER_ID, sourceUserId);
        }
        if (s.get(SessionContext.REQUESTER_ID) == null) {
            s.put(SessionContext.REQUESTER_ID, msg.getReqId());
        }

        try {
            // Normalize profile request if applicable
            String profileId = thisreq.getExtDataInString(Request.PROFILE_ID);
            if (profileId != null && !profileId.isEmpty()) {
                ConnectorRequestUtil.normalizeProfileRequest(thisreq);
            }

            logger.debug("CAConnectorResource: processing request");
            queue.processRequest(thisreq);

        } finally {
            // Audit logging for profile cert requests
            String profileId2 = thisreq.getExtDataInString(Request.PROFILE_ID);
            if (profileId2 != null && !profileId2.isEmpty()) {
                X509CertImpl x509cert = thisreq.getExtDataInCert(Request.REQUEST_ISSUED_CERT);
                if (x509cert != null) {
                    auditor.log(CertRequestProcessedEvent.createSuccessEvent(
                            auditSubjectID, auditRequesterID,
                            ILogger.SIGNED_AUDIT_ACCEPTANCE, x509cert));
                } else {
                    auditor.log(CertRequestProcessedEvent.createFailureEvent(
                            auditSubjectID, auditRequesterID,
                            ILogger.SIGNED_AUDIT_REJECTION,
                            ILogger.SIGNED_AUDIT_EMPTY_VALUE));
                }
            }
            SessionContext.releaseContext();
        }

        IPKIMessage replymsg = new HttpPKIMessage();
        replymsg.fromRequest(thisreq);

        auditor.log(CMS.getLogMessage(
                AuditEvent.INTER_BOUNDARY, auditSubjectID, ILogger.SUCCESS,
                SIGNED_AUDIT_PROTECTION_METHOD_SSL, auditRequestType, auditRequesterID));

        return replymsg;
    }
}
