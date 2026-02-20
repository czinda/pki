//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.connector.IRemoteRequest;
import org.dogtagpki.server.kra.KRAEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.request.KeyRequestRepository;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestQueue;

/**
 * JAX-RS resource replacing the legacy TokenKeyRecoveryServlet CMSServlet.
 * Handles token key recovery requests from the netkey TPS.
 *
 * This is a connector servlet handling inter-subsystem RPC. It receives
 * form-encoded parameters describing the token key recovery request,
 * creates a request in the queue, processes it, and returns the
 * result as a form-encoded response.
 *
 * Input parameters:
 * - CUID: the CUID of the old token
 * - userid: the userid for both old and new tokens
 * - keyid: the key ID in DRM for recovery (alternative to cert)
 * - drm_trans_desKey: DES key wrapped with DRM transport key
 * - drm_trans_aesKey: AES key wrapped with DRM transport key
 * - cert: user cert corresponding to the key to recover
 * - aesKeyWrapAlg: AES key wrap algorithm
 *
 * Output (form-encoded):
 * - status: 0=success, non-zero=error
 * - publicKey: recovered public key
 * - wrappedPrivKey: wrapped user private key
 * - iv_s: initialization vector
 *
 * Legacy URL: /agent/kra/TokenKeyRecovery
 */
@Path("agent/kra/TokenKeyRecovery")
public class KRATokenKeyRecoveryResource {

    private static final Logger logger = LoggerFactory.getLogger(KRATokenKeyRecoveryResource.class);

    @Inject
    KRAEngineQuarkus engineQuarkus;

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces("application/x-www-form-urlencoded")
    public Response tokenKeyRecovery(
            @FormParam(IRemoteRequest.TOKEN_CUID) String cuid,
            @FormParam(IRemoteRequest.KRA_UserId) String userid,
            @FormParam(IRemoteRequest.KRA_RECOVERY_KEYID) String keyid,
            @FormParam(IRemoteRequest.KRA_Trans_DesKey) String desKeyString,
            @FormParam(IRemoteRequest.KRA_Trans_AesKey) String aesKeyString,
            @FormParam(IRemoteRequest.KRA_RECOVERY_CERT) String cert,
            @FormParam(IRemoteRequest.KRA_Aes_Wrap_Alg) String aesKeyWrapAlg) {

        logger.info("KRATokenKeyRecoveryResource: Processing TokenKeyRecovery request");

        KRAEngine engine = engineQuarkus.getEngine();
        KeyRequestRepository requestRepository = engine.getKeyRequestRepository();
        RequestQueue queue = engine.getRequestQueue();

        boolean missingParam = false;
        boolean missingTransDes = false;
        boolean missingTransAes = false;
        boolean missingAesKeyWrapAlg = false;
        String status = "0";
        Request thisreq = null;

        // Validate AES key wrap algorithm
        if (aesKeyWrapAlg == null || aesKeyWrapAlg.isEmpty()) {
            logger.debug("KRATokenKeyRecoveryResource: Missing AES-KeyWrap-alg parameter");
            missingAesKeyWrapAlg = true;
        }

        // Validate CUID
        if (cuid == null || cuid.isEmpty()) {
            logger.warn("KRATokenKeyRecoveryResource: Missing CUID parameter");
            missingParam = true;
        }

        // Validate userid
        if (userid == null || userid.isEmpty()) {
            logger.warn("KRATokenKeyRecoveryResource: Missing userid parameter");
            missingParam = true;
        }

        // Validate transport-wrapped AES key
        if (aesKeyString == null || aesKeyString.isEmpty()) {
            logger.warn("KRATokenKeyRecoveryResource: Missing DRM-transportKey-wrapped AES key");
            missingTransAes = true;
        }

        // Validate transport-wrapped DES key
        if (desKeyString == null || desKeyString.isEmpty()) {
            logger.warn("KRATokenKeyRecoveryResource: Missing DRM-transportKey-wrapped DES key");
            missingTransDes = true;
        }

        // At least one wrapped key (AES or DES) must be present
        if (missingTransAes && missingTransDes) {
            missingParam = true;
        }

        // Must have either cert or keyid
        boolean hasCert = (cert != null && !cert.isEmpty());
        boolean hasKeyid = (keyid != null && !keyid.isEmpty());
        if (!hasCert && !hasKeyid) {
            logger.warn("KRATokenKeyRecoveryResource: Missing both cert and keyid parameters");
            missingParam = true;
        }

        try {
            if (!missingParam) {
                thisreq = requestRepository.createRequest(Request.NETKEY_KEYRECOVERY_REQUEST);

                thisreq.setExtData(Request.REQUESTOR_TYPE, Request.REQUESTOR_NETKEY_RA);
                thisreq.setExtData(Request.NETKEY_ATTR_CUID, cuid);
                thisreq.setExtData(Request.NETKEY_ATTR_USERID, userid);

                if (!missingTransDes) {
                    thisreq.setExtData(Request.NETKEY_ATTR_DRMTRANS_DES_KEY, desKeyString);
                }

                if (!missingTransAes) {
                    thisreq.setExtData(Request.NETKEY_ATTR_DRMTRANS_AES_KEY, aesKeyString);
                }

                if (!missingAesKeyWrapAlg) {
                    logger.debug("KRATokenKeyRecoveryResource: aesKeyWrapAlg: {}", aesKeyWrapAlg);
                    thisreq.setExtData(Request.NETKEY_ATTR_SSKEYGEN_AES_KEY_WRAP_ALG, aesKeyWrapAlg);
                }

                if (hasCert) {
                    thisreq.setExtData(Request.NETKEY_ATTR_USER_CERT, cert);
                    logger.debug("KRATokenKeyRecoveryResource: Received cert parameter");
                }

                if (hasKeyid) {
                    thisreq.setExtData(Request.NETKEY_ATTR_KEYID, keyid);
                    logger.debug("KRATokenKeyRecoveryResource: Received keyid parameter");
                }

                // Process the request through the queue
                queue.processRequest(thisreq);

                Integer result = thisreq.getExtDataInInteger(Request.RESULT);
                if (result != null) {
                    // TPS considers 0 as success; DRM considers 1 as success
                    if (result.intValue() == 1) {
                        status = "0";
                    } else {
                        status = result.toString();
                    }
                } else {
                    status = "7";
                }

                logger.debug("KRATokenKeyRecoveryResource: Processing finished");
            }

            if (thisreq == null) {
                logger.error("KRATokenKeyRecoveryResource: Request is null");
                String value = IRemoteRequest.RESPONSE_STATUS + "=7";
                return Response.ok(value, "application/x-www-form-urlencoded").build();
            }

            // Extract response data from the processed request
            String publicKeyString = thisreq.getExtDataInString("public_key");
            String wrappedPrivKeyString = thisreq.getExtDataInString("wrappedUserPrivate");
            String ivString = thisreq.getExtDataInString("iv_s");

            // Zero out sensitive fields in the request
            thisreq.setExtData("wrappedUserPrivate", "");
            thisreq.setExtData("public_key", "");
            thisreq.setExtData("iv_s", "");
            thisreq.setExtData(Request.NETKEY_ATTR_DRMTRANS_DES_KEY, "");

            // Delete the sensitive fields
            thisreq.deleteExtData("wrappedUserPrivate");
            thisreq.deleteExtData("public_key");
            thisreq.deleteExtData("iv_s");
            thisreq.deleteExtData(Request.NETKEY_ATTR_DRMTRANS_DES_KEY);

            // Commit the cleaned-up request to LDAP
            thisreq.setExtData("delayLDAPCommit", "false");
            requestRepository.updateRequest(thisreq);

            // Build the response
            String value;
            if (!status.equals("0")) {
                value = IRemoteRequest.RESPONSE_STATUS + "=" + status;
            } else {
                StringBuilder sb = new StringBuilder();
                sb.append(IRemoteRequest.RESPONSE_STATUS).append("=0&");
                sb.append(IRemoteRequest.KRA_RESPONSE_Wrapped_PrivKey).append("=");
                sb.append(wrappedPrivKeyString);
                sb.append("&").append(IRemoteRequest.KRA_RESPONSE_PublicKey).append("=");
                sb.append(publicKeyString);
                sb.append("&").append(IRemoteRequest.KRA_RESPONSE_IV_Param).append("=");
                sb.append(ivString);
                value = sb.toString();
            }

            logger.debug("KRATokenKeyRecoveryResource: Response length={}", value.length());
            return Response.ok(value, "application/x-www-form-urlencoded").build();

        } catch (EBaseException e) {
            logger.error("KRATokenKeyRecoveryResource: Error processing token key recovery: {}",
                    e.getMessage(), e);
            String value = IRemoteRequest.RESPONSE_STATUS + "=1";
            return Response.ok(value, "application/x-www-form-urlencoded").build();
        }
    }
}
