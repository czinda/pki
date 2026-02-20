//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

import java.util.Hashtable;

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
import org.dogtagpki.server.kra.KRAEngineConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.request.KeyRequestRepository;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestQueue;

/**
 * JAX-RS resource replacing the legacy GenerateKeyPairServlet CMSServlet.
 * Handles server-side key pair generation requests from netkey RA.
 *
 * Legacy URL: /agent/kra/GenerateKeyPair
 */
@Path("agent/kra/GenerateKeyPair")
public class KRAGenerateKeyPairResource {

    private static final Logger logger = LoggerFactory.getLogger(KRAGenerateKeyPairResource.class);

    @Inject
    KRAEngineQuarkus engineQuarkus;

    private Hashtable<String, String> supportedECCurves;

    private Hashtable<String, String> getSupportedECCurves(KRAEngineConfig config) {
        if (supportedECCurves == null) {
            supportedECCurves = new Hashtable<>();
            String curveList;
            try {
                curveList = config.getString("kra.keygen.curvelist", "nistp256,nistp384,nistp521");
            } catch (EBaseException e) {
                curveList = "nistp256,nistp384,nistp521";
            }
            String[] curves = curveList.split(",");
            for (String curve : curves) {
                supportedECCurves.put(curve, curve);
            }
        }
        return supportedECCurves;
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces("application/x-www-form-urlencoded")
    public Response generateKeyPair(
            @FormParam(IRemoteRequest.TOKEN_CUID) String cuid,
            @FormParam(IRemoteRequest.KRA_UserId) String userid,
            @FormParam(IRemoteRequest.KRA_Trans_DesKey) String desKeyString,
            @FormParam(IRemoteRequest.KRA_Trans_AesKey) String aesKeyString,
            @FormParam(IRemoteRequest.KRA_Aes_Wrap_Alg) String aesWrapAlg,
            @FormParam(IRemoteRequest.KRA_KEYGEN_Archive) String archive,
            @FormParam(IRemoteRequest.KRA_KEYGEN_KeySize) String keysize,
            @FormParam(IRemoteRequest.KRA_KEYGEN_KeyType) String keytype,
            @FormParam(IRemoteRequest.KRA_KEYGEN_EC_KeyCurve) String keycurve) {

        logger.info("KRAGenerateKeyPairResource: Processing GenerateKeyPair request");

        KRAEngine engine = engineQuarkus.getEngine();
        KRAEngineConfig config = engine.getConfig();
        KeyRequestRepository requestRepository = engine.getKeyRequestRepository();
        RequestQueue queue = engine.getRequestQueue();

        boolean missingParam = false;
        String status = "0";
        Request thisreq = null;

        // Validate CUID
        if (cuid == null || cuid.isEmpty()) {
            logger.warn("KRAGenerateKeyPairResource: Missing CUID parameter");
            missingParam = true;
        }

        // Validate userid
        if (userid == null || userid.isEmpty()) {
            logger.warn("KRAGenerateKeyPairResource: Missing userid parameter");
            missingParam = true;
        }

        // Default key type to RSA if not specified
        if (keytype == null || keytype.isEmpty()) {
            keytype = "RSA";
        }

        // Default key size for non-EC keys
        if (!keytype.equals("EC") && (keysize == null || keysize.isEmpty())) {
            keysize = "1024";
        }

        // Validate EC curve
        if (keytype.equals("EC")) {
            if (keycurve == null || keycurve.isEmpty()) {
                keycurve = "nistp256";
            }
            Hashtable<String, String> ecCurves = getSupportedECCurves(config);
            if (!ecCurves.containsKey(keycurve)) {
                logger.warn("KRAGenerateKeyPairResource: Unsupported EC curve: {}", keycurve);
                missingParam = true;
            } else {
                logger.debug("KRAGenerateKeyPairResource: EC curve to generate: {}", keycurve);
            }
        }

        // Validate that at least one wrapped key is present
        boolean wrappedDesPresent = (desKeyString != null && !desKeyString.isEmpty());
        boolean wrappedAesPresent = (aesKeyString != null && !aesKeyString.isEmpty());

        if (!wrappedDesPresent && !wrappedAesPresent) {
            logger.warn("KRAGenerateKeyPairResource: Neither DES nor AES wrapped key provided");
            missingParam = true;
        }

        // Default archive flag
        if (archive == null || archive.isEmpty()) {
            logger.debug("KRAGenerateKeyPairResource: Missing archive flag, defaulting to true");
            archive = "true";
        }

        try {
            if (!missingParam) {
                thisreq = requestRepository.createRequest(Request.NETKEY_KEYGEN_REQUEST);

                thisreq.setExtData(Request.REQUESTOR_TYPE, Request.REQUESTOR_NETKEY_RA);
                thisreq.setExtData(Request.NETKEY_ATTR_CUID, cuid);
                thisreq.setExtData(Request.NETKEY_ATTR_USERID, userid);

                if (wrappedDesPresent) {
                    thisreq.setExtData(Request.NETKEY_ATTR_DRMTRANS_DES_KEY, desKeyString);
                }

                if (wrappedAesPresent) {
                    thisreq.setExtData(Request.NETKEY_ATTR_DRMTRANS_AES_KEY, aesKeyString);
                }

                thisreq.setExtData(Request.NETKEY_ATTR_ARCHIVE_FLAG, archive);
                thisreq.setExtData(Request.NETKEY_ATTR_KEY_SIZE, keysize);
                thisreq.setExtData(Request.NETKEY_ATTR_KEY_TYPE, keytype);
                thisreq.setExtData(Request.NETKEY_ATTR_KEY_EC_CURVE, keycurve);

                if (aesWrapAlg != null && !aesWrapAlg.isEmpty()) {
                    thisreq.setExtData(Request.NETKEY_ATTR_SSKEYGEN_AES_KEY_WRAP_ALG, aesWrapAlg);
                }

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

                logger.debug("KRAGenerateKeyPairResource: Processing finished");
            }

            if (thisreq == null) {
                logger.error("KRAGenerateKeyPairResource: Request is null");
                String value = IRemoteRequest.RESPONSE_STATUS + "=7";
                return Response.ok(value, "application/x-www-form-urlencoded").build();
            }

            String publicKeyString = thisreq.getExtDataInString("public_key");
            String wrappedPrivKeyString = thisreq.getExtDataInString("wrappedUserPrivate");
            String ivString = thisreq.getExtDataInString("iv_s");

            // Zero out sensitive fields in the request
            thisreq.setExtData("wrappedUserPrivate", "");
            thisreq.setExtData("public_key", "");
            thisreq.setExtData("iv_s", "");
            thisreq.setExtData(Request.NETKEY_ATTR_DRMTRANS_DES_KEY, "");

            thisreq.deleteExtData("wrappedUserPrivate");
            thisreq.deleteExtData("public_key");
            thisreq.deleteExtData("iv_s");
            thisreq.deleteExtData(Request.NETKEY_ATTR_DRMTRANS_DES_KEY);

            // Commit the cleaned-up request to LDAP
            thisreq.setExtData("delayLDAPCommit", "false");
            requestRepository.updateRequest(thisreq);

            String value;
            if (!status.equals("0")) {
                value = IRemoteRequest.RESPONSE_STATUS + "=" + status;
            } else {
                StringBuilder sb = new StringBuilder();
                sb.append(IRemoteRequest.RESPONSE_STATUS).append("=0&");
                sb.append(IRemoteRequest.KRA_RESPONSE_Wrapped_PrivKey).append("=");
                sb.append(wrappedPrivKeyString);
                sb.append("&").append(IRemoteRequest.KRA_RESPONSE_IV_Param).append("=");
                sb.append(ivString);
                sb.append("&").append(IRemoteRequest.KRA_RESPONSE_PublicKey).append("=");
                sb.append(publicKeyString);
                value = sb.toString();
            }

            logger.debug("KRAGenerateKeyPairResource: Response length={}", value.length());
            return Response.ok(value, "application/x-www-form-urlencoded").build();

        } catch (EBaseException e) {
            logger.error("KRAGenerateKeyPairResource: Error generating key pair: {}", e.getMessage(), e);
            String value = IRemoteRequest.RESPONSE_STATUS + "=1";
            return Response.ok(value, "application/x-www-form-urlencoded").build();
        }
    }
}
