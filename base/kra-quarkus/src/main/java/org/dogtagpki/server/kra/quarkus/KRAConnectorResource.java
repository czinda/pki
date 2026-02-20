//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;

import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.kra.KRAEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.connector.IPKIMessage;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cms.realm.PKIPrincipalCore;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.connector.HttpPKIMessage;
import com.netscape.cmscore.connector.HttpRequestEncoder;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestQueue;
import com.netscape.cmscore.request.RequestRepository;

import io.quarkus.security.identity.SecurityIdentity;

/**
 * JAX-RS resource replacing the legacy ConnectorServlet for KRA.
 * Handles inter-subsystem RPC (CA->KRA key archival/recovery requests).
 *
 * Legacy URL: /agent/kra/connector
 */
@Path("agent/kra/connector")
public class KRAConnectorResource {

    private static final Logger logger = LoggerFactory.getLogger(KRAConnectorResource.class);
    private static final String SIGNED_AUDIT_PROTECTION_METHOD_SSL = "ssl";

    @Inject
    KRAEngineQuarkus engineQuarkus;

    @Inject
    SecurityIdentity securityIdentity;

    @Context
    SecurityContext securityContext;

    private final HttpRequestEncoder reqEncoder = new HttpRequestEncoder();

    @POST
    @Consumes(MediaType.WILDCARD)
    public Response processRequest(String encodedRequest) {
        logger.info("KRAConnectorResource: Processing connector request");

        KRAEngine engine = engineQuarkus.getEngine();
        Auditor auditor = engine.getAuditor();

        if (!engine.isInRunningState()) {
            logger.error("KRAConnectorResource: Server is not ready");
            return Response.status(Response.Status.SERVICE_UNAVAILABLE).build();
        }

        if (encodedRequest == null || encodedRequest.isEmpty()) {
            logger.warn("KRAConnectorResource: Missing request content");
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        java.security.Principal principal = securityContext.getUserPrincipal();
        if (principal == null) {
            logger.warn("KRAConnectorResource: Not authenticated");
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }

        String sourceUserId = principal.getName();
        String source = principal.getName();

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
            IPKIMessage msg = (IPKIMessage) reqEncoder.decode(encodedRequest);

            String auditRequestType = msg.getReqType();
            String auditRequesterID = msg.getReqId();

            if (auditRequestType != null) auditRequestType = auditRequestType.trim();
            else auditRequestType = ILogger.SIGNED_AUDIT_EMPTY_VALUE;
            if (auditRequesterID != null) auditRequesterID = auditRequesterID.trim();
            else auditRequesterID = ILogger.UNIDENTIFIED;

            IPKIMessage replymsg = processRequest(
                    engine, auditor, source, sourceUserId, msg, token,
                    auditSubjectID, auditRequestType, auditRequesterID);

            String encodedReply = reqEncoder.encode(replymsg);
            return Response.ok(encodedReply, "text/html").build();

        } catch (Exception e) {
            logger.error("KRAConnectorResource: Error processing request", e);
            return Response.serverError().build();
        }
    }

    private IPKIMessage processRequest(
            KRAEngine engine,
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

        logger.debug("KRAConnectorResource: srcid={}", srcid);

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

            // Check for SSK stage transition
            String sskStage = thisreq.getExtDataInString(Request.SSK_STAGE);
            if (sskStage != null && sskStage.equalsIgnoreCase(Request.SSK_STAGE_KEYGEN)) {
                logger.debug("KRAConnectorResource: SSK stage={}", sskStage);
            } else {
                logger.debug("KRAConnectorResource: Found existing request {} for {}", thisreqid, srcid);
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
        logger.debug("KRAConnectorResource: created requestId={}", thisreq.getRequestId());

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

        SessionContext s = SessionContext.getContext();
        if (s.get(SessionContext.USER_ID) == null) {
            s.put(SessionContext.USER_ID, sourceUserId);
        }
        if (s.get(SessionContext.REQUESTER_ID) == null) {
            s.put(SessionContext.REQUESTER_ID, msg.getReqId());
        }

        try {
            logger.debug("KRAConnectorResource: processing request");
            queue.processRequest(thisreq);
        } finally {
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
