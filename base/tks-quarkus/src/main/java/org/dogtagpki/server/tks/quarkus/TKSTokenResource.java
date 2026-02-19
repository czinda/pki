// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later
package org.dogtagpki.server.tks.quarkus;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.util.ArrayList;
import java.util.StringTokenizer;

import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import jakarta.inject.Inject;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.connector.IRemoteRequest;
import org.dogtagpki.server.tks.TKSEngine;
import org.dogtagpki.server.tks.TKSEngineConfig;
import org.dogtagpki.server.tks.servlet.GPParams;
import org.dogtagpki.server.tks.servlet.NistSP800_108KDF;
import org.dogtagpki.server.tks.servlet.SecureChannelProtocol;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.KeyWrapper;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.util.PrettyPrintFormat;
import org.mozilla.jss.pkcs11.PK11SymKey;
import org.mozilla.jss.symkey.SessionKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.ComputeRandomDataRequestProcessedEvent;
import com.netscape.certsrv.logging.event.ComputeSessionKeyRequestProcessedEvent;
import com.netscape.certsrv.logging.event.DiversifyKeyRequestProcessedEvent;
import com.netscape.certsrv.logging.event.EncryptDataRequestProcessedEvent;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmscore.security.JssSubsystem;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * JAX-RS resource replacing the legacy TokenServlet (CMSServlet) for the TKS subsystem.
 *
 * This resource handles all TKS token operations that were previously dispatched
 * by the TokenServlet's process() method. The operations are:
 *
 * - computeSessionKey (SCP01): Computes MAC and encryption session keys, host cryptogram,
 *   and optionally server-side keygen wrapped keys.
 * - computeSessionKey (SCP02): Computes a single session key for SCP02 protocol.
 * - computeSessionKey (SCP03): Computes MAC, encryption, and KEK session keys for SCP03 protocol.
 * - encryptData: Encrypts data (PIN) using TKS master keys.
 * - createKeySetData (diversifyKey): Creates diversified key set data for card personalization.
 * - computeRandomData: Generates cryptographically secure random data.
 *
 * The dispatch logic mirrors the original servlet: it examines the presence and values
 * of specific form parameters to determine which operation to invoke.
 *
 * All responses are returned as text/html with URL-encoded key=value pairs for
 * backward compatibility with the TPS client.
 *
 * Legacy URL: /agent/tks/tokenServlet (via POST)
 */
@Path("agent/tks/tokenServlet")
public class TKSTokenResource {

    private static final Logger logger = LoggerFactory.getLogger(TKSTokenResource.class);

    private static final String TRANSPORT_KEY_NAME = "sharedSecret";

    // Derivation Constants for SCP02
    private static final byte[] C_MACDerivationConstant = { (byte) 0x01, (byte) 0x01 };
    private static final byte[] ENCDerivationConstant = { 0x01, (byte) 0x82 };
    private static final byte[] DEKDerivationConstant = { 0x01, (byte) 0x81 };
    private static final byte[] R_MACDerivationConstant = { 0x01, 0x02 };

    private final PrettyPrintFormat pp = new PrettyPrintFormat(":");

    private String mKeyNickName;
    private String mNewKeyNickName;
    private String mCurrentUID;

    @Inject
    TKSEngineQuarkus engineQuarkus;

    /**
     * Main entry point for all TKS token operations.
     *
     * The dispatch logic mirrors the original TokenServlet.process() method:
     * it examines the presence and values of specific form parameters
     * (card_challenge, protocol, data, newKeyInfo, dataNumBytes, derivationConstant)
     * to determine which operation to invoke.
     *
     * @param request the HTTP servlet request containing form parameters
     * @return text/html response with key=value pairs
     */
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces("text/html")
    public Response processTokenOperation(@Context HttpServletRequest request) {

        logger.info("TKSTokenResource: Processing token operation");

        // TODO: Authentication/authorization integration with Quarkus security.
        // The original servlet calls authenticate(cmsReq) and authorize().
        // In Quarkus, this should be handled by the TKSAclFilter / security layer.
        // For now, extract the current user from the session context if available.

        TKSEngine engine = engineQuarkus.getEngine();

        try {
            // Mirror the original dispatch logic from TokenServlet.process()
            String cardChallenge = request.getParameter(IRemoteRequest.TOKEN_CARD_CHALLENGE);
            String protocol = request.getParameter(IRemoteRequest.CHANNEL_PROTOCOL);
            String derivationConstant = request.getParameter(IRemoteRequest.DERIVATION_CONSTANT);

            setDefaultSlotAndKeyName(request);

            String responseBody;

            if (cardChallenge != null && protocol == null) {
                // SCP01 compute session key
                responseBody = processComputeSessionKey(request);

            } else if (request.getParameter(IRemoteRequest.TOKEN_DATA) != null) {
                // Encrypt data
                responseBody = processEncryptData(request);

            } else if (request.getParameter(IRemoteRequest.TOKEN_NEW_KEYINFO) != null) {
                // Diversify key (create key set data)
                responseBody = processDiversifyKey(request);

            } else if (request.getParameter(IRemoteRequest.TOKEN_DATA_NUM_BYTES) != null) {
                // Compute random data
                responseBody = processComputeRandomData(request);

            } else if (protocol != null && protocol.contains("2") && derivationConstant != null) {
                // SCP02 compute session key
                responseBody = processComputeSessionKeySCP02(request);

            } else if (protocol != null && protocol.contains("3")) {
                // SCP03 compute session keys
                responseBody = processComputeSessionKeysSCP03(request);

            } else {
                logger.error("TKSTokenResource: Cannot determine operation from request parameters");
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity("status=1")
                        .type("text/html")
                        .build();
            }

            return Response.ok(responseBody, "text/html").build();

        } catch (EBaseException e) {
            logger.error("TKSTokenResource: Error processing token operation: {}", e.getMessage(), e);
            return Response.serverError()
                    .entity("status=1")
                    .type("text/html")
                    .build();
        }
    }

    // ========================================================================
    // Compute Session Key - SCP01
    // ========================================================================

    private String processComputeSessionKey(HttpServletRequest req) throws EBaseException {

        logger.debug("TKSTokenResource.processComputeSessionKey: entering");

        byte[] card_challenge, host_challenge, keyInfo, xCUID, session_key, xKDD;
        byte nistSP800_108KdfOnKeyVersion = (byte) 0xff;
        boolean nistSP800_108KdfUseCuidAsKdd = false;
        byte[] card_crypto, host_cryptogram, input_card_crypto;
        byte[] xcard_challenge, xhost_challenge;
        byte[] enc_session_key, xkeyInfo;
        String errorMsg = "";
        String badParams = "";
        String transportKeyName = "";

        String rCUID = req.getParameter(IRemoteRequest.TOKEN_CUID);
        String rKDD = req.getParameter("KDD");
        if (rKDD == null || rKDD.isEmpty()) {
            logger.debug("TKSTokenResource: KDD not supplied, set to CUID");
            rKDD = rCUID;
        }

        String keySet = req.getParameter(IRemoteRequest.TOKEN_KEYSET);
        if (keySet == null || keySet.isEmpty()) {
            keySet = "defKeySet";
        }
        logger.debug("TKSTokenResource.processComputeSessionKey: keySet={}", keySet);

        boolean serversideKeygen = false;
        byte[] drm_trans_wrapped_desKey = null;
        byte[] aes_wrapped_desKey = null;
        byte[] drm_trans_wrapped_aesKey = null;
        SymmetricKey desKey = null;
        SymmetricKey aesKey = null;
        SymmetricKey kek_key;

        TKSEngine engine = engineQuarkus.getEngine();
        TKSEngineConfig sconfig = engine.getConfig();
        boolean isCryptoValidate = true;
        boolean missingParam = false;
        Exception missingSetting_exception = null;

        session_key = null;
        card_crypto = null;
        host_cryptogram = null;
        enc_session_key = null;

        String agentId = getAgentId();

        String auditMessage = CMS.getLogMessage(
                AuditEvent.COMPUTE_SESSION_KEY_REQUEST,
                rCUID, rKDD, ILogger.SUCCESS, agentId);
        audit(auditMessage);

        String kek_wrapped_desKeyString = null;
        String kek_wrapped_aesKeyString = null;
        String keycheck_s = null;

        String useSoftToken_s = sconfig.getString("tks.useSoftToken", "true");
        if (!useSoftToken_s.equalsIgnoreCase("true"))
            useSoftToken_s = "false";

        String rServersideKeygen = req.getParameter(IRemoteRequest.SERVER_SIDE_KEYGEN);
        if ("true".equals(rServersideKeygen)) {
            serversideKeygen = true;
        }

        try {
            isCryptoValidate = sconfig.getBoolean("cardcryptogram.validate.enable", true);
        } catch (EBaseException eee) {
            // use default
        }

        transportKeyName = getSharedSecretName(sconfig);

        String rcard_challenge = req.getParameter(IRemoteRequest.TOKEN_CARD_CHALLENGE);
        String rhost_challenge = req.getParameter(IRemoteRequest.TOKEN_HOST_CHALLENGE);
        String rKeyInfo = req.getParameter(IRemoteRequest.TOKEN_KEYINFO);
        String rcard_cryptogram = req.getParameter(IRemoteRequest.TOKEN_CARD_CRYPTOGRAM);

        if (isNullOrEmpty(rCUID)) {
            badParams += " CUID,";
            missingParam = true;
        }
        if (isNullOrEmpty(rKDD)) {
            badParams += " KDD,";
            missingParam = true;
        }
        if (isNullOrEmpty(rcard_challenge)) {
            badParams += " card_challenge,";
            missingParam = true;
        }
        if (isNullOrEmpty(rhost_challenge)) {
            badParams += " host_challenge,";
            missingParam = true;
        }
        if (isNullOrEmpty(rKeyInfo)) {
            badParams += " KeyInfo,";
            missingParam = true;
        }

        String selectedToken = null;
        String keyNickName = null;
        boolean sameCardCrypto = true;

        xCUID = null;
        xKDD = null;
        xkeyInfo = null;

        if (!missingParam) {
            xCUID = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(rCUID);
            if (xCUID == null || xCUID.length != 10) {
                badParams += " CUID length,";
                missingParam = true;
            }

            xKDD = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(rKDD);
            if (xKDD == null || xKDD.length != 10) {
                badParams += " KDD length,";
                missingParam = true;
            }

            xkeyInfo = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(rKeyInfo);
            if (xkeyInfo == null || xkeyInfo.length != 2) {
                badParams += " KeyInfo length,";
                missingParam = true;
            }

            xcard_challenge = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(rcard_challenge);
            if (xcard_challenge == null || xcard_challenge.length != 8) {
                badParams += " card_challenge length,";
                missingParam = true;
            }

            xhost_challenge = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(rhost_challenge);
            if (xhost_challenge == null || xhost_challenge.length != 8) {
                badParams += " host_challenge length,";
                missingParam = true;
            }
        }

        if (!missingParam) {
            card_challenge = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(rcard_challenge);
            host_challenge = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(rhost_challenge);
            keyInfo = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(rKeyInfo);

            try {
                nistSP800_108KdfOnKeyVersion = readNistSP800_108KdfOnKeyVersion(keySet);
                nistSP800_108KdfUseCuidAsKdd = readNistSP800_108KdfUseCuidAsKdd(keySet);
            } catch (Exception e) {
                missingSetting_exception = e;
                logger.debug("TKSTokenResource: Exception reading NIST SP800-108 KDF config: {}", e.toString());
            }

            String keyInfoMap = "tks." + keySet + ".mk_mappings." + rKeyInfo;
            String mappingValue = sconfig.getString(keyInfoMap, null);
            if (mappingValue == null) {
                selectedToken = sconfig.getString("tks.defaultSlot", CryptoUtil.INTERNAL_TOKEN_NAME);
                keyNickName = rKeyInfo;
            } else {
                StringTokenizer st = new StringTokenizer(mappingValue, ":");
                if (st.hasMoreTokens())
                    selectedToken = st.nextToken();
                if (st.hasMoreTokens())
                    keyNickName = st.nextToken();
            }

            if (selectedToken != null && keyNickName != null && missingSetting_exception == null) {

                try {
                    byte[] macKeyArray = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(
                            sconfig.getString("tks." + keySet + ".mac_key"));

                    SecureChannelProtocol protocol = new SecureChannelProtocol();
                    SymmetricKey macKey = protocol.computeSessionKey_SCP01(
                            SecureChannelProtocol.macType, selectedToken,
                            keyNickName, card_challenge, host_challenge, keyInfo,
                            nistSP800_108KdfOnKeyVersion, nistSP800_108KdfUseCuidAsKdd,
                            xCUID, xKDD, macKeyArray, useSoftToken_s, keySet, transportKeyName);

                    session_key = protocol.wrapSessionKey(selectedToken, macKey, null);
                    if (session_key == null) {
                        throw new Exception("Can't compute session key!");
                    }

                    byte[] encKeyArray = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(
                            sconfig.getString("tks." + keySet + ".auth_key"));

                    SymmetricKey encKey = protocol.computeSessionKey_SCP01(
                            SecureChannelProtocol.encType, selectedToken,
                            keyNickName, card_challenge, host_challenge, keyInfo,
                            nistSP800_108KdfOnKeyVersion, nistSP800_108KdfUseCuidAsKdd,
                            xCUID, xKDD, encKeyArray, useSoftToken_s, keySet, transportKeyName);

                    enc_session_key = protocol.wrapSessionKey(selectedToken, encKey, null);
                    if (enc_session_key == null) {
                        throw new Exception("Can't compute enc session key!");
                    }

                    if (serversideKeygen) {
                        byte[] kekKeyArray = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(
                                sconfig.getString("tks." + keySet + ".kek_key"));

                        kek_key = protocol.computeKEKKey_SCP01(
                                selectedToken, keyNickName, keyInfo,
                                nistSP800_108KdfOnKeyVersion, nistSP800_108KdfUseCuidAsKdd,
                                xCUID, xKDD, kekKeyArray, useSoftToken_s, keySet, transportKeyName);

                        if (kek_key == null) {
                            throw new Exception("Can't compute kek key!");
                        }

                        if (useSoftToken_s.equals("true")) {
                            desKey = protocol.generateSymKey(CryptoUtil.INTERNAL_TOKEN_NAME);
                            aesKey = protocol.generateAESSymKey(CryptoUtil.INTERNAL_TOKEN_NAME, 128);
                        } else {
                            desKey = protocol.generateSymKey(selectedToken);
                            aesKey = protocol.generateAESSymKey(selectedToken, 128);
                        }

                        if (desKey == null) {
                            throw new Exception("Can't generate key encryption key");
                        }
                        if (aesKey == null) {
                            throw new Exception("Can't generate AES key encryption key");
                        }

                        byte[] encDesKey = protocol.ecbEncrypt(kek_key, desKey, selectedToken);
                        byte[] encAesKey = protocol.ecbEncrypt(kek_key, aesKey, selectedToken);

                        kek_wrapped_desKeyString = org.mozilla.jss.netscape.security.util.Utils.SpecialEncode(encDesKey);
                        kek_wrapped_aesKeyString = org.mozilla.jss.netscape.security.util.Utils.SpecialEncode(encAesKey);

                        byte[] keycheck = protocol.computeKeyCheck(desKey, selectedToken);
                        keycheck_s = org.mozilla.jss.netscape.security.util.Utils.SpecialEncode(keycheck);

                        // Wrap desKey and aesKey with DRM transport cert
                        String drmTransNickname = sconfig.getString("tks.drm_transport_cert_nickname", "");
                        if (isNullOrEmpty(drmTransNickname)) {
                            throw new Exception("Can't find DRM transport certificate nickname");
                        }

                        X509Certificate drmTransCert = CryptoManager.getInstance().findCertByNickname(drmTransNickname);
                        CryptoToken token;
                        if (useSoftToken_s.equals("true")) {
                            token = CryptoUtil.getCryptoToken(null);
                        } else {
                            token = CryptoUtil.getCryptoToken(selectedToken);
                        }
                        PublicKey pubKey = drmTransCert.getPublicKey();
                        String pubKeyAlgo = pubKey.getAlgorithm();

                        KeyWrapper keyWrapper;
                        if (pubKeyAlgo.equals("EC")) {
                            keyWrapper = token.getKeyWrapper(KeyWrapAlgorithm.AES_ECB);
                            keyWrapper.initWrap(pubKey, null);
                        } else {
                            boolean useOAEP = sconfig.getBoolean("keyWrap.useOAEP", false);
                            KeyWrapAlgorithm wrapAlg = useOAEP ? KeyWrapAlgorithm.RSA_OAEP : KeyWrapAlgorithm.RSA;
                            keyWrapper = token.getKeyWrapper(wrapAlg);
                            OAEPParameterSpec params = null;
                            if (useOAEP) {
                                params = new OAEPParameterSpec("SHA-256", "MGF1",
                                        MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
                            }
                            keyWrapper.initWrap(pubKey, params);
                        }

                        drm_trans_wrapped_desKey = keyWrapper.wrap(desKey);
                        drm_trans_wrapped_aesKey = keyWrapper.wrap(aesKey);

                        // Wrap desKey with aesKey
                        KeyWrapper aesKeyWrap = token.getKeyWrapper(KeyWrapAlgorithm.AES_CBC_PAD);
                        aesKeyWrap.initWrap(aesKey, new IVParameterSpec(
                                new byte[EncryptionAlgorithm.AES_128_CBC_PAD.getIVLength()]));
                        aes_wrapped_desKey = aesKeyWrap.wrap(desKey);
                    }

                    byte[] authKeyArray = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(
                            sconfig.getString("tks." + keySet + ".auth_key"));

                    host_cryptogram = protocol.computeCryptogram_SCP01(
                            selectedToken, keyNickName, card_challenge, host_challenge,
                            xkeyInfo, nistSP800_108KdfOnKeyVersion, nistSP800_108KdfUseCuidAsKdd,
                            xCUID, xKDD, SecureChannelProtocol.HOST_CRYPTOGRAM,
                            authKeyArray, useSoftToken_s, keySet, transportKeyName);

                    if (host_cryptogram == null) {
                        throw new Exception("Can't compute host cryptogram!");
                    }

                    card_crypto = protocol.computeCryptogram_SCP01(
                            selectedToken, keyNickName, card_challenge, host_challenge,
                            xkeyInfo, nistSP800_108KdfOnKeyVersion, nistSP800_108KdfUseCuidAsKdd,
                            xCUID, xKDD, SecureChannelProtocol.CARD_CRYPTOGRAM,
                            authKeyArray, useSoftToken_s, keySet, transportKeyName);

                    if (card_crypto == null) {
                        throw new Exception("Can't compute card cryptogram!");
                    }

                    if (isCryptoValidate) {
                        if (rcard_cryptogram == null) {
                            throw new Exception("Missing card cryptogram");
                        }
                        input_card_crypto = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(rcard_cryptogram);

                        if (card_crypto.length == input_card_crypto.length) {
                            for (int i = 0; i < card_crypto.length; i++) {
                                if (card_crypto[i] != input_card_crypto[i]) {
                                    sameCardCrypto = false;
                                    break;
                                }
                            }
                        } else {
                            sameCardCrypto = false;
                        }
                    }

                } catch (Exception e) {
                    logger.debug("TKSTokenResource: Computing Session Key: {}", e.toString());
                    if (isCryptoValidate)
                        sameCardCrypto = false;
                }
            }
        }

        // Build response
        String outputString = "";
        String encSessionKeyString = "";
        String drm_trans_wrapped_desKeyString = "";
        String aes_wrapped_desKeyString = "";
        String drm_trans_wrapped_aesKeyString = "";
        String cryptogram = "";
        String status = "0";

        if (session_key != null && session_key.length > 0) {
            outputString = org.mozilla.jss.netscape.security.util.Utils.SpecialEncode(session_key);
        } else {
            status = "1";
        }

        if (enc_session_key != null && enc_session_key.length > 0) {
            encSessionKeyString = org.mozilla.jss.netscape.security.util.Utils.SpecialEncode(enc_session_key);
        } else {
            status = "1";
        }

        if (serversideKeygen) {
            if (drm_trans_wrapped_desKey != null && drm_trans_wrapped_desKey.length > 0) {
                drm_trans_wrapped_desKeyString = org.mozilla.jss.netscape.security.util.Utils.SpecialEncode(drm_trans_wrapped_desKey);
            } else {
                status = "1";
            }
            if (drm_trans_wrapped_aesKey != null && drm_trans_wrapped_aesKey.length > 0) {
                drm_trans_wrapped_aesKeyString = org.mozilla.jss.netscape.security.util.Utils.SpecialEncode(drm_trans_wrapped_aesKey);
            } else {
                status = "1";
            }
            if (aes_wrapped_desKey != null && aes_wrapped_desKey.length > 0) {
                aes_wrapped_desKeyString = org.mozilla.jss.netscape.security.util.Utils.SpecialEncode(aes_wrapped_desKey);
            } else {
                status = "1";
            }
        }

        if (host_cryptogram != null && host_cryptogram.length > 0) {
            cryptogram = org.mozilla.jss.netscape.security.util.Utils.SpecialEncode(host_cryptogram);
        } else {
            if (status.equals("0")) {
                status = "2";
            }
        }

        if (selectedToken == null || keyNickName == null) {
            if (status.equals("0")) {
                status = "4";
            }
        }

        if (!sameCardCrypto) {
            if (status.equals("0")) {
                status = "5";
            }
        }

        if (missingSetting_exception != null) {
            status = "6";
        }

        if (missingParam) {
            status = "3";
        }

        String value;
        if (!status.equals("0")) {
            errorMsg = getErrorMessage(status, badParams);
            value = IRemoteRequest.RESPONSE_STATUS + "=" + status;
        } else {
            if (serversideKeygen) {
                StringBuilder sb = new StringBuilder();
                sb.append(IRemoteRequest.RESPONSE_STATUS).append("=0&");
                sb.append(IRemoteRequest.TKS_RESPONSE_SessionKey).append("=").append(outputString);
                sb.append("&").append(IRemoteRequest.TKS_RESPONSE_HostCryptogram).append("=").append(cryptogram);
                sb.append("&").append(IRemoteRequest.TKS_RESPONSE_EncSessionKey).append("=").append(encSessionKeyString);
                sb.append("&").append(IRemoteRequest.TKS_RESPONSE_KEK_DesKey).append("=").append(kek_wrapped_desKeyString);
                sb.append("&").append(IRemoteRequest.TKS_RESPONSE_KEK_AesKey).append("=").append(kek_wrapped_aesKeyString);
                sb.append("&").append(IRemoteRequest.TKS_RESPONSE_KeyCheck).append("=").append(keycheck_s);
                sb.append("&").append(IRemoteRequest.TKS_RESPONSE_DRM_Trans_DesKey).append("=").append(drm_trans_wrapped_desKeyString);
                sb.append("&").append(IRemoteRequest.TKS_RESPONSE_DRM_Trans_AesKey).append("=").append(drm_trans_wrapped_aesKeyString);
                value = sb.toString();
            } else {
                StringBuilder sb = new StringBuilder();
                sb.append(IRemoteRequest.RESPONSE_STATUS).append("=0&");
                sb.append(IRemoteRequest.TKS_RESPONSE_SessionKey).append("=").append(outputString);
                sb.append("&").append(IRemoteRequest.TKS_RESPONSE_HostCryptogram).append("=").append(cryptogram);
                sb.append("&").append(IRemoteRequest.TKS_RESPONSE_EncSessionKey).append("=").append(encSessionKeyString);
                value = sb.toString();
            }
        }

        // Audit logging
        Auditor auditor = engine.getAuditor();
        if (status.equals("0")) {
            ComputeSessionKeyRequestProcessedEvent event = ComputeSessionKeyRequestProcessedEvent.success(
                    logBytesToHex(xCUID), logBytesToHex(xKDD), status, agentId,
                    isCryptoValidate ? "true" : "false",
                    serversideKeygen ? "true" : "false",
                    selectedToken, keyNickName, keySet,
                    logKeyInfoVersion(xkeyInfo),
                    "0x" + Integer.toHexString(nistSP800_108KdfOnKeyVersion & 0x000000FF),
                    Boolean.toString(nistSP800_108KdfUseCuidAsKdd));
            auditor.log(event);
        } else {
            ComputeSessionKeyRequestProcessedEvent event = ComputeSessionKeyRequestProcessedEvent.failure(
                    logBytesToHex(xCUID), logBytesToHex(xKDD), status, agentId,
                    isCryptoValidate ? "true" : "false",
                    serversideKeygen ? "true" : "false",
                    selectedToken, keyNickName, keySet,
                    logKeyInfoVersion(xkeyInfo),
                    "0x" + Integer.toHexString(nistSP800_108KdfOnKeyVersion & 0x000000FF),
                    Boolean.toString(nistSP800_108KdfUseCuidAsKdd),
                    errorMsg);
            auditor.log(event);
        }

        return value;
    }

    // ========================================================================
    // Compute Session Key - SCP02
    // ========================================================================

    private String processComputeSessionKeySCP02(HttpServletRequest req) throws EBaseException {

        logger.debug("TKSTokenResource.processComputeSessionKeySCP02: entering");

        String errorMsg = "";
        String badParams = "";
        String transportKeyName = "";
        boolean missingParam = false;
        String selectedToken = null;
        String keyNickName = null;
        byte[] drm_trans_wrapped_desKey = null;
        byte[] xKDD = null;
        byte nistSP800_108KdfOnKeyVersion = (byte) 0xff;
        boolean nistSP800_108KdfUseCuidAsKdd = false;

        TKSEngine engine = engineQuarkus.getEngine();
        TKSEngineConfig sconfig = engine.getConfig();

        boolean isCryptoValidate = false;
        byte[] keyInfo, xCUID = null, session_key = null;
        Exception missingSettingException = null;

        String rCUID = req.getParameter(IRemoteRequest.TOKEN_CUID);
        String rKDD = req.getParameter(IRemoteRequest.TOKEN_KDD);
        String rKeyInfo = req.getParameter(IRemoteRequest.TOKEN_KEYINFO);

        if (isNullOrEmpty(rKeyInfo)) {
            badParams += " KeyInfo,";
            missingParam = true;
        }

        keyInfo = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(rKeyInfo);

        String keySet = req.getParameter(IRemoteRequest.TOKEN_KEYSET);
        if (keySet == null || keySet.isEmpty()) {
            keySet = "defKeySet";
        }

        boolean serversideKeygen = false;
        String rDerivationConstant = req.getParameter(IRemoteRequest.DERIVATION_CONSTANT);
        String rSequenceCounter = req.getParameter(IRemoteRequest.SEQUENCE_COUNTER);

        if (isNullOrEmpty(rDerivationConstant)) {
            badParams += " derivation_constant,";
            missingParam = true;
        }
        if (isNullOrEmpty(rSequenceCounter)) {
            badParams += " sequence_counter,";
            missingParam = true;
        }

        String agentId = getAgentId();

        String auditMessage = CMS.getLogMessage(
                AuditEvent.COMPUTE_SESSION_KEY_REQUEST,
                rCUID, rKDD, ILogger.SUCCESS, agentId);
        audit(auditMessage);

        if (!missingParam) {
            xCUID = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(rCUID);
            if (xCUID == null || xCUID.length != 10) {
                badParams += " CUID length,";
                missingParam = true;
            }

            if (isNullOrEmpty(rKDD)) {
                badParams += " KDD,";
                missingParam = true;
            }

            xKDD = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(rKDD);
            if (xKDD == null || xKDD.length != 10) {
                badParams += " KDD length,";
                missingParam = true;
            }

            keyInfo = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(rKeyInfo);
            if (keyInfo == null || keyInfo.length != 2) {
                badParams += " KeyInfo length,";
                missingParam = true;
            }

            try {
                nistSP800_108KdfOnKeyVersion = readNistSP800_108KdfOnKeyVersion(keySet);
                nistSP800_108KdfUseCuidAsKdd = readNistSP800_108KdfUseCuidAsKdd(keySet);
            } catch (Exception e) {
                missingSettingException = e;
                logger.debug("TKSTokenResource: Exception reading NIST SP800-108 KDF config: {}", e.toString());
            }
        }

        // Resolve token and key nickname from config mappings
        String keyInfoMap = "tks." + keySet + ".mk_mappings." + rKeyInfo;
        String mappingValue = sconfig.getString(keyInfoMap, null);
        if (mappingValue == null) {
            selectedToken = sconfig.getString("tks.defaultSlot", CryptoUtil.INTERNAL_TOKEN_NAME);
            keyNickName = rKeyInfo;
        } else {
            StringTokenizer st = new StringTokenizer(mappingValue, ":");
            if (st.hasMoreTokens())
                selectedToken = st.nextToken();
            if (st.hasMoreTokens())
                keyNickName = st.nextToken();
        }

        String useSoftToken_s = sconfig.getString("tks.useSoftToken", "true");
        if (!useSoftToken_s.equalsIgnoreCase("true"))
            useSoftToken_s = "false";

        String rServersideKeygen = req.getParameter(IRemoteRequest.SERVER_SIDE_KEYGEN);
        if ("true".equals(rServersideKeygen)) {
            serversideKeygen = true;
        }

        transportKeyName = null;
        try {
            transportKeyName = getSharedSecretName(sconfig);
        } catch (EBaseException e) {
            logger.debug("TKSTokenResource.processComputeSessionKeySCP02: Can't find transport key name");
        }

        try {
            isCryptoValidate = sconfig.getBoolean("cardcryptogram.validate.enable", true);
        } catch (EBaseException eee) {
            // use default
        }

        String dek_wrapped_desKeyString = null;
        String keycheck_s = null;
        boolean errorFound = false;

        if (selectedToken != null && keyNickName != null && transportKeyName != null && missingSettingException == null) {
            try {
                byte[] macKeyArray = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(
                        sconfig.getString("tks." + keySet + ".mac_key"));
                byte[] sequenceCounter = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(rSequenceCounter);
                byte[] derivationConstant = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(rDerivationConstant);

                session_key = SessionKey.ComputeSessionKeySCP02(
                        selectedToken, keyNickName, keyInfo,
                        nistSP800_108KdfOnKeyVersion, nistSP800_108KdfUseCuidAsKdd,
                        xCUID, xKDD, macKeyArray, sequenceCounter, derivationConstant,
                        useSoftToken_s, keySet, transportKeyName);

                if (session_key == null) {
                    throw new EBaseException("Can't compute session key for SCP02!");
                }

                // Handle DEK key for server-side keygen
                if (derivationConstant[0] == DEKDerivationConstant[0]
                        && derivationConstant[1] == DEKDerivationConstant[1] && serversideKeygen) {

                    PK11SymKey desKey2;
                    if (useSoftToken_s.equals("true")) {
                        desKey2 = SessionKey.GenerateSymkey(CryptoUtil.INTERNAL_TOKEN_NAME);
                    } else {
                        desKey2 = SessionKey.GenerateSymkey(selectedToken);
                    }
                    if (desKey2 == null) {
                        throw new EBaseException("Can't generate key encryption key");
                    }

                    CryptoToken token;
                    if (useSoftToken_s.equals("true")) {
                        token = CryptoUtil.getCryptoToken(null);
                    } else {
                        token = CryptoUtil.getCryptoToken(selectedToken);
                    }

                    PK11SymKey sharedSecret = getSharedSecretKey(sconfig);
                    if (sharedSecret == null) {
                        throw new EBaseException("Can't find shared secret sym key!");
                    }

                    PK11SymKey dekKey = SessionKey.UnwrapSessionKeyWithSharedSecret(
                            token.getName(), sharedSecret, session_key);
                    if (dekKey == null) {
                        throw new EBaseException("Can't unwrap DEK key onto the token!");
                    }

                    byte[] encDesKey = SessionKey.ECBencrypt(dekKey, desKey2);
                    if (encDesKey == null) {
                        throw new EBaseException("Can't encrypt DEK key!");
                    }

                    dek_wrapped_desKeyString = org.mozilla.jss.netscape.security.util.Utils.SpecialEncode(encDesKey);

                    byte[] keycheck = SessionKey.ComputeKeyCheck(desKey2);
                    if (keycheck == null) {
                        throw new EBaseException("Can't compute key check for encrypted DEK key!");
                    }
                    keycheck_s = org.mozilla.jss.netscape.security.util.Utils.SpecialEncode(keycheck);

                    // Wrap desKey with DRM transport cert
                    String drmTransNickname = sconfig.getString("tks.drm_transport_cert_nickname", "");
                    if (isNullOrEmpty(drmTransNickname)) {
                        throw new EBaseException("Can't find DRM transport certificate nickname");
                    }

                    X509Certificate drmTransCert = CryptoManager.getInstance().findCertByNickname(drmTransNickname);
                    PublicKey pubKey = drmTransCert.getPublicKey();
                    String pubKeyAlgo = pubKey.getAlgorithm();

                    KeyWrapper keyWrapper;
                    if (pubKeyAlgo.equals("EC")) {
                        keyWrapper = token.getKeyWrapper(KeyWrapAlgorithm.AES_ECB);
                        keyWrapper.initWrap(pubKey, null);
                    } else {
                        boolean useOAEP = sconfig.getBoolean("keyWrap.useOAEP", false);
                        KeyWrapAlgorithm wrapAlg = useOAEP ? KeyWrapAlgorithm.RSA_OAEP : KeyWrapAlgorithm.RSA;
                        keyWrapper = token.getKeyWrapper(wrapAlg);
                        OAEPParameterSpec params = null;
                        if (useOAEP) {
                            params = new OAEPParameterSpec("SHA-256", "MGF1",
                                    MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
                        }
                        keyWrapper.initWrap(pubKey, params);
                    }

                    drm_trans_wrapped_desKey = keyWrapper.wrap(desKey2);
                }

            } catch (Exception e) {
                logger.debug("TKSTokenResource.computeSessionKeySCP02: {}", e.toString());
                errorFound = true;
            }
        }

        // Build response
        String status = "0";
        String outputString = "";
        boolean statusDeclared = false;

        if (session_key != null && session_key.length > 0 && !errorFound) {
            outputString = org.mozilla.jss.netscape.security.util.Utils.SpecialEncode(session_key);
        } else {
            status = "1";
            statusDeclared = true;
        }

        if (selectedToken == null || keyNickName == null) {
            if (!statusDeclared) {
                status = "4";
                statusDeclared = true;
            }
        }

        if (missingSettingException != null) {
            if (!statusDeclared) {
                status = "6";
                statusDeclared = true;
            }
        }

        if (missingParam) {
            status = "3";
        }

        String value;
        String drm_trans_wrapped_desKeyString = null;

        if (!status.equals("0")) {
            errorMsg = getErrorMessage(status, badParams);
            value = IRemoteRequest.RESPONSE_STATUS + "=" + status;
        } else {
            if (serversideKeygen) {
                if (drm_trans_wrapped_desKey != null && drm_trans_wrapped_desKey.length > 0) {
                    drm_trans_wrapped_desKeyString =
                            org.mozilla.jss.netscape.security.util.Utils.SpecialEncode(drm_trans_wrapped_desKey);
                }

                StringBuilder sb = new StringBuilder();
                sb.append(IRemoteRequest.RESPONSE_STATUS).append("=0&");
                sb.append(IRemoteRequest.TKS_RESPONSE_SessionKey).append("=").append(outputString);
                if (drm_trans_wrapped_desKeyString != null) {
                    sb.append("&").append(IRemoteRequest.TKS_RESPONSE_DRM_Trans_DesKey).append("=").append(drm_trans_wrapped_desKeyString);
                }
                if (dek_wrapped_desKeyString != null) {
                    sb.append("&").append(IRemoteRequest.TKS_RESPONSE_KEK_DesKey).append("=").append(dek_wrapped_desKeyString);
                }
                if (keycheck_s != null) {
                    sb.append("&").append(IRemoteRequest.TKS_RESPONSE_KeyCheck).append("=").append(keycheck_s);
                }
                value = sb.toString();
            } else {
                StringBuilder sb = new StringBuilder();
                sb.append(IRemoteRequest.RESPONSE_STATUS).append("=0&");
                sb.append(IRemoteRequest.TKS_RESPONSE_SessionKey).append("=").append(outputString);
                value = sb.toString();
            }
        }

        // Audit logging
        Auditor auditor = engine.getAuditor();
        if (status.equals("0")) {
            ComputeSessionKeyRequestProcessedEvent event = ComputeSessionKeyRequestProcessedEvent.success(
                    logBytesToHex(xCUID), logBytesToHex(xKDD), status, agentId,
                    isCryptoValidate ? "true" : "false",
                    serversideKeygen ? "true" : "false",
                    selectedToken, keyNickName, keySet,
                    logKeyInfoVersion(keyInfo),
                    "0x" + Integer.toHexString(nistSP800_108KdfOnKeyVersion & 0x000000FF),
                    Boolean.toString(nistSP800_108KdfUseCuidAsKdd));
            auditor.log(event);
        } else {
            ComputeSessionKeyRequestProcessedEvent event = ComputeSessionKeyRequestProcessedEvent.failure(
                    logBytesToHex(xCUID), logBytesToHex(xKDD), status, agentId,
                    isCryptoValidate ? "true" : "false",
                    serversideKeygen ? "true" : "false",
                    selectedToken, keyNickName, keySet,
                    logKeyInfoVersion(keyInfo),
                    "0x" + Integer.toHexString(nistSP800_108KdfOnKeyVersion & 0x000000FF),
                    Boolean.toString(nistSP800_108KdfUseCuidAsKdd),
                    errorMsg);
            auditor.log(event);
        }

        return value;
    }

    // ========================================================================
    // Compute Session Keys - SCP03
    // ========================================================================

    private String processComputeSessionKeysSCP03(HttpServletRequest req) throws EBaseException {

        String method = "TKSTokenResource.processComputeSessionKeysSCP03:";
        logger.debug("{} entering", method);

        byte[] card_challenge, host_challenge, xCUID, xKDD;
        byte[] card_crypto, host_cryptogram, input_card_crypto;
        byte[] xcard_challenge, xhost_challenge;
        byte[] enc_session_key, xkeyInfo, mac_session_key, kek_session_key;
        String errorMsg = "";
        String badParams = "";
        String transportKeyName = "";

        String rCUID = req.getParameter(IRemoteRequest.TOKEN_CUID);
        String rKDD = req.getParameter("KDD");
        if (rKDD == null || rKDD.isEmpty()) {
            rKDD = rCUID;
        }

        String keySet = req.getParameter(IRemoteRequest.TOKEN_KEYSET);
        if (keySet == null || keySet.isEmpty()) {
            keySet = "defKeySet";
        }

        GPParams gp3Params = readGPSettings(keySet);

        boolean serversideKeygen = false;
        TKSEngine engine = engineQuarkus.getEngine();
        TKSEngineConfig sconfig = engine.getConfig();

        boolean isCryptoValidate = true;
        boolean missingParam = false;
        Exception missingSetting_exception = null;

        mac_session_key = null;
        kek_session_key = null;
        card_crypto = null;
        host_cryptogram = null;
        enc_session_key = null;

        String agentId = getAgentId();

        String auditMessage = CMS.getLogMessage(
                AuditEvent.COMPUTE_SESSION_KEY_REQUEST,
                rCUID, rKDD, ILogger.SUCCESS, agentId);
        audit(auditMessage);

        String kek_wrapped_desKeyString = null;
        String kek_wrapped_aesKeyString = null;
        String keycheck_s = null;
        String keycheck_aes_s = null;

        String useSoftToken_s = sconfig.getString("tks.useSoftToken", "true");
        if (!useSoftToken_s.equalsIgnoreCase("true"))
            useSoftToken_s = "false";

        String rServersideKeygen = req.getParameter(IRemoteRequest.SERVER_SIDE_KEYGEN);
        if ("true".equals(rServersideKeygen)) {
            serversideKeygen = true;
        }

        try {
            isCryptoValidate = sconfig.getBoolean("cardcryptogram.validate.enable", true);
        } catch (EBaseException eee) {
            // use default
        }

        transportKeyName = getSharedSecretName(sconfig);

        String rcard_challenge = req.getParameter(IRemoteRequest.TOKEN_CARD_CHALLENGE);
        String rhost_challenge = req.getParameter(IRemoteRequest.TOKEN_HOST_CHALLENGE);
        String rKeyInfo = req.getParameter(IRemoteRequest.TOKEN_KEYINFO);
        String rcard_cryptogram = req.getParameter(IRemoteRequest.TOKEN_CARD_CRYPTOGRAM);

        if (isNullOrEmpty(rCUID)) { badParams += " CUID,"; missingParam = true; }
        if (isNullOrEmpty(rKDD)) { badParams += " KDD,"; missingParam = true; }
        if (isNullOrEmpty(rcard_challenge)) { badParams += " card_challenge,"; missingParam = true; }
        if (isNullOrEmpty(rhost_challenge)) { badParams += " host_challenge,"; missingParam = true; }
        if (isNullOrEmpty(rcard_cryptogram)) { badParams += " card_cryptogram,"; missingParam = true; }
        if (isNullOrEmpty(rKeyInfo)) { badParams += " KeyInfo,"; missingParam = true; }

        String selectedToken = null;
        String keyNickName = null;
        boolean sameCardCrypto = true;

        xCUID = null;
        xKDD = null;
        xkeyInfo = null;
        xcard_challenge = null;
        xhost_challenge = null;

        if (!missingParam) {
            xCUID = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(rCUID);
            if (xCUID == null || xCUID.length != 10) { badParams += " CUID length,"; missingParam = true; }

            xKDD = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(rKDD);
            if (xKDD == null || xKDD.length != 10) { badParams += " KDD length,"; missingParam = true; }

            xkeyInfo = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(rKeyInfo);
            if (xkeyInfo == null || xkeyInfo.length != 3) { badParams += " KeyInfo length,"; missingParam = true; }

            xcard_challenge = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(rcard_challenge);
            if (xcard_challenge == null || xcard_challenge.length != 8) { badParams += " card_challenge length,"; missingParam = true; }

            xhost_challenge = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(rhost_challenge);
            if (xhost_challenge == null || xhost_challenge.length != 8) { badParams += " host_challenge length,"; missingParam = true; }
        }

        ArrayList<String> serverSideValues = null;

        if (!missingParam) {
            card_challenge = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(rcard_challenge);
            host_challenge = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(rhost_challenge);

            String keyInfoMap = "tks." + keySet + ".mk_mappings." + rKeyInfo.substring(0, 6);
            String mappingValue = sconfig.getString(keyInfoMap, null);
            if (mappingValue == null) {
                selectedToken = sconfig.getString("tks.defaultSlot", "internal");
                keyNickName = rKeyInfo;
            } else {
                StringTokenizer st = new StringTokenizer(mappingValue, ":");
                if (st.hasMoreTokens()) selectedToken = st.nextToken();
                if (st.hasMoreTokens()) keyNickName = st.nextToken();
            }

            SymmetricKey macSessionKey = null;
            SymmetricKey encSessionKey = null;
            SymmetricKey kekSessionKey = null;

            if (selectedToken != null && keyNickName != null && missingSetting_exception == null) {

                try {
                    byte[] macKeyArray = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(
                            sconfig.getString("tks." + keySet + ".mac_key"));

                    SecureChannelProtocol protocol = new SecureChannelProtocol(SecureChannelProtocol.PROTOCOL_THREE);

                    macSessionKey = protocol.computeSessionKey_SCP03(
                            selectedToken, keyNickName, xkeyInfo,
                            SecureChannelProtocol.macType, macKeyArray, keySet,
                            xCUID, xKDD, xhost_challenge, xcard_challenge,
                            transportKeyName, gp3Params);

                    mac_session_key = protocol.wrapSessionKey(selectedToken, macSessionKey, null);
                    if (mac_session_key == null) {
                        throw new Exception("Can't get mac session key bytes");
                    }

                    byte[] encKeyArray = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(
                            sconfig.getString("tks." + keySet + ".auth_key"));

                    encSessionKey = protocol.computeSessionKey_SCP03(
                            selectedToken, keyNickName, xkeyInfo,
                            SecureChannelProtocol.encType, encKeyArray, keySet,
                            xCUID, xKDD, xhost_challenge, xcard_challenge,
                            transportKeyName, gp3Params);

                    enc_session_key = protocol.wrapSessionKey(selectedToken, encSessionKey, null);
                    if (enc_session_key == null) {
                        throw new Exception("Can't compute enc session key!");
                    }

                    byte[] kekKeyArray = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(
                            sconfig.getString("tks." + keySet + ".kek_key"));

                    kekSessionKey = protocol.computeSessionKey_SCP03(
                            selectedToken, keyNickName, xkeyInfo,
                            SecureChannelProtocol.kekType, kekKeyArray, keySet,
                            xCUID, xKDD, xhost_challenge, xcard_challenge,
                            transportKeyName, gp3Params);

                    kek_session_key = protocol.wrapSessionKey(selectedToken, kekSessionKey, null);

                    // Server-side keygen values
                    if (serversideKeygen) {
                        try {
                            serverSideValues = calculateServerSideKeygenValues(
                                    useSoftToken_s, selectedToken, kekSessionKey, protocol, sconfig);
                        } catch (EBaseException e) {
                            logger.debug("{} Can't calculate server side keygen values", method);
                        }
                    }

                    try {
                        isCryptoValidate = sconfig.getBoolean("cardcryptogram.validate.enable", true);
                    } catch (EBaseException eee) {
                        // use default
                    }

                    ByteArrayOutputStream contextStream = new ByteArrayOutputStream();
                    try {
                        contextStream.write(host_challenge);
                        contextStream.write(card_challenge);
                    } catch (IOException e) {
                        throw new EBaseException("Error calculating derivation data!");
                    }

                    host_cryptogram = protocol.computeCryptogram_SCP03(
                            macSessionKey, selectedToken, contextStream.toByteArray(),
                            NistSP800_108KDF.HOST_CRYPTO_KDF_CONSTANT);

                    if (isCryptoValidate) {
                        if (rcard_cryptogram == null) {
                            throw new Exception("Missing card cryptogram");
                        }
                        input_card_crypto = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(rcard_cryptogram);
                        card_crypto = protocol.computeCryptogram_SCP03(
                                macSessionKey, selectedToken, contextStream.toByteArray(),
                                NistSP800_108KDF.CARD_CRYPTO_KDF_CONSTANT);

                        if (!cryptogramsAreEqual(input_card_crypto, card_crypto)) {
                            throw new Exception("Card cryptogram mismatch!");
                        }
                    }

                } catch (Exception e) {
                    logger.debug("{} Computing Session Key: {}", method, e.toString());
                    if (isCryptoValidate)
                        sameCardCrypto = false;
                }
            }
        }

        // Build response
        String encSessionKeyString = "";
        String macSessionKeyString = "";
        String kekSessionKeyString = "";
        String drm_trans_wrapped_desKeyString = "";
        String drm_trans_wrapped_aesKeyString = "";
        String cryptogram = "";
        String status = "0";

        if (enc_session_key != null && enc_session_key.length > 0) {
            encSessionKeyString = org.mozilla.jss.netscape.security.util.Utils.SpecialEncode(enc_session_key);
        } else {
            status = "1";
        }

        if (mac_session_key != null && mac_session_key.length > 0) {
            macSessionKeyString = org.mozilla.jss.netscape.security.util.Utils.SpecialEncode(mac_session_key);
        } else {
            status = "1";
        }

        if (kek_session_key != null && kek_session_key.length > 0) {
            kekSessionKeyString = org.mozilla.jss.netscape.security.util.Utils.SpecialEncode(kek_session_key);
        } else {
            status = "1";
        }

        // Server-side keygen values:
        // 0: kek_wrapped_desKey, 1: keycheck_des, 2: keycheck_aes,
        // 3: drm_trans_desKey, 4: drm_trans_aesKey, 5: kek_wrapped_aesKey
        if (serversideKeygen && serverSideValues != null) {
            if (serverSideValues.size() >= 3) {
                drm_trans_wrapped_desKeyString = serverSideValues.get(3);
                kek_wrapped_desKeyString = serverSideValues.get(0);
                keycheck_s = serverSideValues.get(1);
                keycheck_aes_s = serverSideValues.get(2);

                if (serverSideValues.size() >= 5) {
                    drm_trans_wrapped_aesKeyString = serverSideValues.get(4);
                }
                if (serverSideValues.size() >= 6) {
                    kek_wrapped_aesKeyString = serverSideValues.get(5);
                }
            } else {
                status = "1";
            }
        }

        if (host_cryptogram != null && host_cryptogram.length > 0) {
            cryptogram = org.mozilla.jss.netscape.security.util.Utils.SpecialEncode(host_cryptogram);
        } else {
            if (status.equals("0")) status = "2";
        }

        if (selectedToken == null || keyNickName == null) {
            if (status.equals("0")) status = "4";
        }

        if (!sameCardCrypto) {
            if (status.equals("0")) status = "5";
        }

        if (missingSetting_exception != null) {
            status = "6";
        }

        if (missingParam) {
            status = "3";
        }

        String value;
        if (!status.equals("0")) {
            errorMsg = getErrorMessage(status, badParams);
            value = IRemoteRequest.RESPONSE_STATUS + "=" + status;
        } else {
            if (serversideKeygen) {
                StringBuilder sb = new StringBuilder();
                sb.append(IRemoteRequest.RESPONSE_STATUS).append("=0&");
                sb.append(IRemoteRequest.TKS_RESPONSE_MacSessionKey).append("=").append(macSessionKeyString);
                sb.append("&").append(IRemoteRequest.TKS_RESPONSE_HostCryptogram).append("=").append(cryptogram);
                sb.append("&").append(IRemoteRequest.TKS_RESPONSE_EncSessionKey).append("=").append(encSessionKeyString);
                sb.append("&").append(IRemoteRequest.TKS_RESPONSE_KekSessionKey).append("=").append(kekSessionKeyString);
                sb.append("&").append(IRemoteRequest.TKS_RESPONSE_KEK_DesKey).append("=").append(kek_wrapped_desKeyString);
                sb.append("&").append(IRemoteRequest.TKS_RESPONSE_KEK_AesKey).append("=").append(kek_wrapped_aesKeyString);
                sb.append("&").append(IRemoteRequest.TKS_RESPONSE_KeyCheck).append("=").append(keycheck_aes_s);
                sb.append("&").append(IRemoteRequest.TKS_RESPONSE_KeyCheck_Des).append("=").append(keycheck_s);
                sb.append("&").append(IRemoteRequest.TKS_RESPONSE_DRM_Trans_DesKey).append("=").append(drm_trans_wrapped_desKeyString);
                sb.append("&").append(IRemoteRequest.TKS_RESPONSE_DRM_Trans_AesKey).append("=").append(drm_trans_wrapped_aesKeyString);
                value = sb.toString();
            } else {
                StringBuilder sb = new StringBuilder();
                sb.append(IRemoteRequest.RESPONSE_STATUS).append("=0&");
                sb.append(IRemoteRequest.TKS_RESPONSE_MacSessionKey).append("=").append(macSessionKeyString);
                sb.append("&").append(IRemoteRequest.TKS_RESPONSE_HostCryptogram).append("=").append(cryptogram);
                sb.append("&").append(IRemoteRequest.TKS_RESPONSE_EncSessionKey).append("=").append(encSessionKeyString);
                sb.append("&").append(IRemoteRequest.TKS_RESPONSE_KekSessionKey).append("=").append(kekSessionKeyString);
                value = sb.toString();
            }
        }

        // Audit logging
        Auditor auditor = engine.getAuditor();
        if (status.equals("0")) {
            ComputeSessionKeyRequestProcessedEvent event = ComputeSessionKeyRequestProcessedEvent.success(
                    logBytesToHex(xCUID), logBytesToHex(xKDD), status, agentId,
                    isCryptoValidate ? "true" : "false",
                    serversideKeygen ? "true" : "false",
                    selectedToken, keyNickName, keySet,
                    logKeyInfoVersion(xkeyInfo), null, null);
            auditor.log(event);
        } else {
            ComputeSessionKeyRequestProcessedEvent event = ComputeSessionKeyRequestProcessedEvent.failure(
                    logBytesToHex(xCUID), logBytesToHex(xKDD), status, agentId,
                    isCryptoValidate ? "true" : "false",
                    serversideKeygen ? "true" : "false",
                    selectedToken, keyNickName, keySet,
                    logKeyInfoVersion(xkeyInfo), null, null, errorMsg);
            auditor.log(event);
        }

        return value;
    }

    // ========================================================================
    // Encrypt Data
    // ========================================================================

    private String processEncryptData(HttpServletRequest req) throws EBaseException {

        logger.debug("TKSTokenResource.processEncryptData: entering");

        byte[] keyInfo, xCUID, encryptedData, xkeyInfo, xKDD;
        byte nistSP800_108KdfOnKeyVersion = (byte) 0xff;
        boolean nistSP800_108KdfUseCuidAsKdd = false;
        Exception missingSetting_exception = null;

        boolean missingParam = false;
        byte[] data = null;
        boolean isRandom = true;
        String errorMsg = "";
        String badParams = "";

        TKSEngine engine = engineQuarkus.getEngine();
        TKSEngineConfig sconfig = engine.getConfig();

        encryptedData = null;
        String rdata = req.getParameter(IRemoteRequest.TOKEN_DATA);
        String rKeyInfo = req.getParameter(IRemoteRequest.TOKEN_KEYINFO);
        String rCUID = req.getParameter(IRemoteRequest.TOKEN_CUID);
        String protocolValue = req.getParameter(IRemoteRequest.CHANNEL_PROTOCOL);

        String rKDD = req.getParameter("KDD");
        if (rKDD == null || rKDD.isEmpty()) {
            rKDD = rCUID;
        }

        String keySet = req.getParameter(IRemoteRequest.TOKEN_KEYSET);
        if (keySet == null || keySet.isEmpty()) {
            keySet = "defKeySet";
        }

        String agentId = getAgentId();

        String s_isRandom = sconfig.getString("tks.EncryptData.isRandom", "true");
        if (s_isRandom.equalsIgnoreCase("false")) {
            isRandom = false;
        }

        String auditMessage = CMS.getLogMessage(
                AuditEvent.ENCRYPT_DATA_REQUEST,
                rCUID, rKDD, ILogger.SUCCESS, agentId, s_isRandom);
        audit(auditMessage);

        GPParams gp3Params = readGPSettings(keySet);

        if (isRandom) {
            try {
                JssSubsystem jssSubsystem = engine.getJSSSubsystem();
                SecureRandom random = jssSubsystem.getRandomNumberGenerator();
                data = new byte[16];
                random.nextBytes(data);
            } catch (Exception e) {
                logger.debug("TKSTokenResource.processEncryptData: {}", e.toString());
                badParams += " Random Number,";
                missingParam = true;
            }
        } else if (isNullOrEmpty(rdata)) {
            badParams += " data,";
            missingParam = true;
        }

        if (isNullOrEmpty(rCUID)) { badParams += " CUID,"; missingParam = true; }
        if (isNullOrEmpty(rKDD)) { badParams += " KDD,"; missingParam = true; }
        if (isNullOrEmpty(rKeyInfo)) { badParams += " KeyInfo,"; missingParam = true; }

        xCUID = null;
        xKDD = null;
        xkeyInfo = null;

        if (!missingParam) {
            xCUID = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(rCUID);
            if (xCUID == null || xCUID.length != 10) { badParams += " CUID length,"; missingParam = true; }

            xKDD = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(rKDD);
            if (xKDD == null || xKDD.length != 10) { badParams += " KDD length,"; missingParam = true; }

            xkeyInfo = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(rKeyInfo);
            if (xkeyInfo == null || (xkeyInfo.length != 2 && xkeyInfo.length != 3)) {
                badParams += " KeyInfo length,";
                missingParam = true;
            }
        }

        String useSoftToken_s = sconfig.getString("tks.useSoftToken", "true");
        if (!useSoftToken_s.equalsIgnoreCase("true"))
            useSoftToken_s = "false";

        String selectedToken = null;
        String keyNickName = null;

        if (!missingParam) {
            try {
                nistSP800_108KdfOnKeyVersion = readNistSP800_108KdfOnKeyVersion(keySet);
                nistSP800_108KdfUseCuidAsKdd = readNistSP800_108KdfUseCuidAsKdd(keySet);
            } catch (Exception e) {
                missingSetting_exception = e;
            }

            if (!isRandom)
                data = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(rdata);

            keyInfo = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(rKeyInfo);

            String keyInfoMap = "tks." + keySet + ".mk_mappings." + rKeyInfo.substring(0, 6);
            String mappingValue = sconfig.getString(keyInfoMap, null);
            if (mappingValue == null) {
                selectedToken = sconfig.getString("tks.defaultSlot", CryptoUtil.INTERNAL_TOKEN_NAME);
                keyNickName = rKeyInfo;
            } else {
                StringTokenizer st = new StringTokenizer(mappingValue, ":");
                selectedToken = st.nextToken();
                keyNickName = st.nextToken();
            }

            int protocolInt = SecureChannelProtocol.PROTOCOL_ONE;
            try {
                protocolInt = Integer.parseInt(protocolValue);
            } catch (NumberFormatException nfe) {
                protocolInt = SecureChannelProtocol.PROTOCOL_ONE;
            }

            if (protocolInt <= 0 || protocolInt > 20) {
                protocolInt = 1;
            }

            byte[] kekKeyArray = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(
                    sconfig.getString("tks." + keySet + ".kek_key"));

            if (missingSetting_exception == null) {
                SecureChannelProtocol protocol = new SecureChannelProtocol(protocolInt);

                if (protocolInt != SecureChannelProtocol.PROTOCOL_THREE) {
                    encryptedData = protocol.encryptData(
                            selectedToken, keyNickName, data, keyInfo,
                            nistSP800_108KdfOnKeyVersion, nistSP800_108KdfUseCuidAsKdd,
                            xCUID, xKDD, kekKeyArray, useSoftToken_s, keySet);
                } else {
                    encryptedData = protocol.encryptData_SCP03(
                            selectedToken, keyNickName, data, xkeyInfo,
                            nistSP800_108KdfOnKeyVersion, nistSP800_108KdfUseCuidAsKdd,
                            xCUID, xKDD, kekKeyArray, useSoftToken_s, keySet, gp3Params);
                }
            }
        }

        // Build response
        String value;
        String status = "0";

        if (encryptedData != null && encryptedData.length > 0) {
            value = IRemoteRequest.RESPONSE_STATUS + "=0&"
                    + IRemoteRequest.TOKEN_DATA + "="
                    + org.mozilla.jss.netscape.security.util.Utils.SpecialEncode(data)
                    + "&" + IRemoteRequest.TKS_RESPONSE_EncryptedData + "="
                    + org.mozilla.jss.netscape.security.util.Utils.SpecialEncode(encryptedData);
        } else if (missingSetting_exception != null) {
            status = "6";
            errorMsg = "Problem reading required configuration value.";
            value = "status=" + status;
        } else if (missingParam) {
            if (badParams.endsWith(",")) {
                badParams = badParams.substring(0, badParams.length() - 1);
            }
            errorMsg = "Missing input parameters: " + badParams;
            status = "3";
            value = IRemoteRequest.RESPONSE_STATUS + "=" + status;
        } else {
            errorMsg = "Problem encrypting data.";
            status = "1";
            value = IRemoteRequest.RESPONSE_STATUS + "=" + status;
        }

        // Audit logging
        Auditor auditor = engine.getAuditor();
        if (status.equals("0")) {
            EncryptDataRequestProcessedEvent event = EncryptDataRequestProcessedEvent.success(
                    logBytesToHex(xCUID), logBytesToHex(xKDD), status, agentId,
                    s_isRandom, selectedToken, keyNickName, keySet,
                    logKeyInfoVersion(xkeyInfo),
                    "0x" + Integer.toHexString(nistSP800_108KdfOnKeyVersion & 0x000000FF),
                    Boolean.toString(nistSP800_108KdfUseCuidAsKdd));
            auditor.log(event);
        } else {
            EncryptDataRequestProcessedEvent event = EncryptDataRequestProcessedEvent.failure(
                    logBytesToHex(xCUID), logBytesToHex(xKDD), status, agentId,
                    s_isRandom, selectedToken, keyNickName, keySet,
                    logKeyInfoVersion(xkeyInfo),
                    "0x" + Integer.toHexString(nistSP800_108KdfOnKeyVersion & 0x000000FF),
                    Boolean.toString(nistSP800_108KdfUseCuidAsKdd),
                    errorMsg);
            auditor.log(event);
        }

        return value;
    }

    // ========================================================================
    // Diversify Key (Create Key Set Data)
    // ========================================================================

    private String processDiversifyKey(HttpServletRequest req) throws EBaseException {

        String method = "TKSTokenResource.processDiversifyKey:";
        logger.debug("{} entering", method);

        byte[] KeySetData, xCUID, xKDD;
        String oldKeyNickName = null;
        String newKeyNickName = null;

        byte nistSP800_108KdfOnKeyVersion = (byte) 0xff;
        boolean nistSP800_108KdfUseCuidAsKdd = false;
        byte[] xkeyInfo = null, xnewkeyInfo = null;
        Exception missingSetting_exception = null;

        boolean missingParam = false;
        String errorMsg = "";
        String badParams = "";
        byte[] xWrappedDekKey = null;

        TKSEngine engine = engineQuarkus.getEngine();
        TKSEngineConfig sconfig = engine.getConfig();

        String rnewKeyInfo = req.getParameter(IRemoteRequest.TOKEN_NEW_KEYINFO);
        String newMasterKeyName = req.getParameter(IRemoteRequest.TOKEN_NEW_KEYINFO);
        String oldMasterKeyName = req.getParameter(IRemoteRequest.TOKEN_KEYINFO);
        String rCUID = req.getParameter(IRemoteRequest.TOKEN_CUID);

        String rKDD = req.getParameter("KDD");
        if (rKDD == null || rKDD.isEmpty()) {
            rKDD = rCUID;
        }

        String rProtocol = req.getParameter(IRemoteRequest.CHANNEL_PROTOCOL);
        String rWrappedDekKey = req.getParameter(IRemoteRequest.WRAPPED_DEK_SESSION_KEY);
        int protocol = 1;

        String keySet = req.getParameter(IRemoteRequest.TOKEN_KEYSET);
        if (keySet == null || keySet.isEmpty()) {
            keySet = "defKeySet";
        }

        // G&D 256 Key Rollover Support
        String oldKeySet = req.getParameter(IRemoteRequest.TOKEN_OLD_KEYSET);

        String agentId = getAgentId();

        String auditMessage = CMS.getLogMessage(
                AuditEvent.DIVERSIFY_KEY_REQUEST,
                rCUID, rKDD, ILogger.SUCCESS, agentId,
                oldMasterKeyName, newMasterKeyName);
        audit(auditMessage);

        if (isNullOrEmpty(rCUID)) { badParams += " CUID,"; missingParam = true; }
        if (isNullOrEmpty(rKDD)) { badParams += " KDD,"; missingParam = true; }
        if (isNullOrEmpty(rnewKeyInfo)) { badParams += " newKeyInfo,"; missingParam = true; }
        if (isNullOrEmpty(oldMasterKeyName)) { badParams += " KeyInfo,"; missingParam = true; }

        xCUID = null;
        xKDD = null;

        if (!missingParam) {
            xkeyInfo = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(oldMasterKeyName);
            if (xkeyInfo == null || (xkeyInfo.length != 2 && xkeyInfo.length != 3)) {
                badParams += " KeyInfo length,";
                missingParam = true;
            }
            xnewkeyInfo = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(newMasterKeyName);
            if (xnewkeyInfo == null || (xnewkeyInfo.length != 2 && xnewkeyInfo.length != 3)) {
                badParams += " NewKeyInfo length,";
                missingParam = true;
            }

            if (rProtocol != null) {
                try {
                    protocol = Integer.parseInt(rProtocol);
                } catch (NumberFormatException e) {
                    protocol = 1;
                }
            }

            if (protocol == 2) {
                if (isNullOrEmpty(rWrappedDekKey)) {
                    badParams += " WrappedDekKey,";
                    missingParam = true;
                } else {
                    xWrappedDekKey = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(rWrappedDekKey);
                }
            }
        }

        String useSoftToken_s = sconfig.getString("tks.useSoftToken", "true");
        if (!useSoftToken_s.equalsIgnoreCase("true"))
            useSoftToken_s = "false";

        KeySetData = null;
        if (!missingParam) {
            xCUID = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(rCUID);
            if (xCUID == null || xCUID.length != 10) {
                badParams += " CUID length,";
                missingParam = true;
            }

            xKDD = org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(rKDD);
            if (xKDD == null || xKDD.length != 10) {
                badParams += " KDD length,";
                missingParam = true;
            }
        }

        if (!missingParam) {
            try {
                nistSP800_108KdfOnKeyVersion = readNistSP800_108KdfOnKeyVersion(keySet);
                nistSP800_108KdfUseCuidAsKdd = readNistSP800_108KdfUseCuidAsKdd(keySet);
            } catch (Exception e) {
                missingSetting_exception = e;
            }

            if (mKeyNickName != null)
                oldMasterKeyName = mKeyNickName;
            if (mNewKeyNickName != null)
                newMasterKeyName = mNewKeyNickName;

            String tokKeyInfo = req.getParameter(IRemoteRequest.TOKEN_KEYINFO);
            tokKeyInfo = tokKeyInfo.substring(0, 6);
            String oldKeyInfoMap = "tks." + keySet + ".mk_mappings." + tokKeyInfo;

            // G&D 256 Key Rollover Support
            if (oldKeySet != null)
                oldKeyInfoMap = "tks." + oldKeySet + ".mk_mappings." + tokKeyInfo;

            String oldMappingValue = sconfig.getString(oldKeyInfoMap, null);
            String oldSelectedToken;
            if (oldMappingValue == null) {
                oldSelectedToken = sconfig.getString("tks.defaultSlot", CryptoUtil.INTERNAL_TOKEN_NAME);
                oldKeyNickName = req.getParameter(IRemoteRequest.TOKEN_KEYINFO);
            } else {
                StringTokenizer st = new StringTokenizer(oldMappingValue, ":");
                oldSelectedToken = st.nextToken();
                oldKeyNickName = st.nextToken();
            }

            String newKeyInfoMap = "tks." + keySet + ".mk_mappings." + rnewKeyInfo.substring(0, 6);
            String newMappingValue = sconfig.getString(newKeyInfoMap, null);
            String newSelectedToken;
            if (newMappingValue == null) {
                newSelectedToken = sconfig.getString("tks.defaultSlot", CryptoUtil.INTERNAL_TOKEN_NAME);
                newKeyNickName = rnewKeyInfo;
            } else {
                StringTokenizer st = new StringTokenizer(newMappingValue, ":");
                newSelectedToken = st.nextToken();
                newKeyNickName = st.nextToken();
            }

            byte[] kekKeyArray = getDevKeyArray("kek_key", sconfig, keySet);
            byte[] macKeyArray = getDevKeyArray("auth_key", sconfig, keySet);
            byte[] encKeyArray = getDevKeyArray("mac_key", sconfig, keySet);

            GPParams gp3Params = readGPSettings(keySet);

            // G&D 256 Key Rollover Support
            GPParams oldGp3Params = gp3Params;
            if (oldKeySet != null) {
                oldGp3Params = readGPSettings(oldKeySet);
            }

            SecureChannelProtocol secProtocol = new SecureChannelProtocol(protocol);

            if (missingSetting_exception == null) {
                if (protocol == 1 || protocol == 3) {
                    KeySetData = secProtocol.diversifyKey(
                            oldSelectedToken, newSelectedToken,
                            oldKeyNickName, newKeyNickName,
                            xkeyInfo, xnewkeyInfo,
                            nistSP800_108KdfOnKeyVersion, nistSP800_108KdfUseCuidAsKdd,
                            xCUID, xKDD,
                            kekKeyArray, encKeyArray, macKeyArray,
                            useSoftToken_s, keySet, (byte) protocol, gp3Params, oldGp3Params);

                } else if (protocol == 2) {
                    KeySetData = SessionKey.DiversifyKey(
                            oldSelectedToken, newSelectedToken,
                            oldKeyNickName, newKeyNickName,
                            xkeyInfo, xnewkeyInfo,
                            nistSP800_108KdfOnKeyVersion, nistSP800_108KdfUseCuidAsKdd,
                            xCUID, xKDD,
                            (protocol == 2) ? xWrappedDekKey : kekKeyArray,
                            useSoftToken_s, keySet, (byte) protocol);
                }
            }
        }

        // Build response
        String value;
        String status = "0";

        if (KeySetData != null && KeySetData.length > 1) {
            value = IRemoteRequest.RESPONSE_STATUS + "=0&"
                    + IRemoteRequest.TKS_RESPONSE_KeySetData + "="
                    + org.mozilla.jss.netscape.security.util.Utils.SpecialEncode(KeySetData);
        } else if (missingSetting_exception != null) {
            status = "6";
            errorMsg = "Problem reading required configuration value.";
            value = "status=" + status;
        } else if (missingParam) {
            status = "3";
            if (badParams.endsWith(",")) {
                badParams = badParams.substring(0, badParams.length() - 1);
            }
            errorMsg = "Missing input parameters: " + badParams;
            value = IRemoteRequest.RESPONSE_STATUS + "=" + status;
        } else {
            errorMsg = "Problem diversifying key data.";
            status = "1";
            value = IRemoteRequest.RESPONSE_STATUS + "=" + status;
        }

        // Audit logging
        Auditor auditor = engine.getAuditor();
        if (status.equals("0")) {
            DiversifyKeyRequestProcessedEvent event = DiversifyKeyRequestProcessedEvent.success(
                    logBytesToHex(xCUID), logBytesToHex(xKDD), status, agentId,
                    oldKeyNickName, newKeyNickName, keySet,
                    logKeyInfoVersion(xkeyInfo), logKeyInfoVersion(xnewkeyInfo),
                    "0x" + Integer.toHexString(nistSP800_108KdfOnKeyVersion & 0x000000FF),
                    Boolean.toString(nistSP800_108KdfUseCuidAsKdd));
            auditor.log(event);
        } else {
            DiversifyKeyRequestProcessedEvent event = DiversifyKeyRequestProcessedEvent.failure(
                    logBytesToHex(xCUID), logBytesToHex(xKDD), status, agentId,
                    oldKeyNickName, newKeyNickName, keySet,
                    logKeyInfoVersion(xkeyInfo), logKeyInfoVersion(xnewkeyInfo),
                    "0x" + Integer.toHexString(nistSP800_108KdfOnKeyVersion & 0x000000FF),
                    Boolean.toString(nistSP800_108KdfUseCuidAsKdd),
                    errorMsg);
            auditor.log(event);
        }

        return value;
    }

    // ========================================================================
    // Compute Random Data
    // ========================================================================

    private String processComputeRandomData(HttpServletRequest req) throws EBaseException {

        logger.debug("TKSTokenResource.processComputeRandomData: entering");

        byte[] randomData = null;
        String status = "0";
        String errorMsg = "";
        String badParams = "";
        boolean missingParam = false;
        int dataSize = 0;

        String agentId = getAgentId();

        String sDataSize = req.getParameter(IRemoteRequest.TOKEN_DATA_NUM_BYTES);
        if (isNullOrEmpty(sDataSize)) {
            badParams += " Random Data size, ";
            missingParam = true;
            status = "1";
        } else {
            try {
                dataSize = Integer.parseInt(sDataSize.trim());
            } catch (NumberFormatException nfe) {
                badParams += " Random Data size, ";
                missingParam = true;
                status = "1";
            }
        }

        logger.debug("TKSTokenResource.processComputeRandomData: data size requested: {}", dataSize);

        String auditMessage = CMS.getLogMessage(
                AuditEvent.COMPUTE_RANDOM_DATA_REQUEST,
                ILogger.SUCCESS, agentId);
        audit(auditMessage);

        if (!missingParam) {
            try {
                TKSEngine engine = engineQuarkus.getEngine();
                JssSubsystem jssSubsystem = engine.getJSSSubsystem();
                SecureRandom random = jssSubsystem.getRandomNumberGenerator();
                randomData = new byte[dataSize];
                random.nextBytes(randomData);
            } catch (Exception e) {
                logger.debug("TKSTokenResource.processComputeRandomData: {}", e.toString());
                errorMsg = "Can't generate random data!";
                status = "2";
            }
        }

        String randomDataOut = "";
        if (status.equals("0")) {
            if (randomData != null && randomData.length == dataSize) {
                randomDataOut = org.mozilla.jss.netscape.security.util.Utils.SpecialEncode(randomData);
            } else {
                status = "2";
                errorMsg = "Can't convert random data!";
            }
        }

        if (status.equals("1") && missingParam) {
            if (badParams.endsWith(",")) {
                badParams = badParams.substring(0, badParams.length() - 1);
            }
            errorMsg = "Missing input parameters :" + badParams;
        }

        String value = IRemoteRequest.RESPONSE_STATUS + "=" + status;
        if (status.equals("0")) {
            value = value + "&" + IRemoteRequest.TKS_RESPONSE_RandomData + "=" + randomDataOut;
        }

        // Audit logging
        TKSEngine engine = engineQuarkus.getEngine();
        Auditor auditor = engine.getAuditor();

        if (status.equals("0")) {
            ComputeRandomDataRequestProcessedEvent event = ComputeRandomDataRequestProcessedEvent.success(
                    status, agentId);
            auditor.log(event);
        } else {
            ComputeRandomDataRequestProcessedEvent event = ComputeRandomDataRequestProcessedEvent.failure(
                    status, agentId, errorMsg);
            auditor.log(event);
        }

        return value;
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /**
     * Sets the default slot and key name based on the request parameters.
     * This resolves key nickname mappings from the TKS configuration.
     */
    private void setDefaultSlotAndKeyName(HttpServletRequest req) {
        try {
            String keySet = req.getParameter(IRemoteRequest.TOKEN_KEYSET);
            if (keySet == null || keySet.isEmpty()) {
                keySet = "defKeySet";
            }

            TKSEngine engine = engineQuarkus.getEngine();
            TKSEngineConfig config = engine.getConfig();
            String masterKeyPrefix = config.getString("tks.master_key_prefix", null);
            String temp = req.getParameter(IRemoteRequest.TOKEN_KEYINFO);
            String keyInfoMap = "tks." + keySet + ".mk_mappings." + temp;
            String mappingValue = config.getString(keyInfoMap, null);
            if (mappingValue != null) {
                StringTokenizer st = new StringTokenizer(mappingValue, ":");
                int tokenNumber = 0;
                while (st.hasMoreTokens()) {
                    String currentToken = st.nextToken();
                    if (tokenNumber == 1)
                        mKeyNickName = currentToken;
                    tokenNumber++;
                }
            }

            if (req.getParameter(IRemoteRequest.TOKEN_NEW_KEYINFO) != null) {
                temp = req.getParameter(IRemoteRequest.TOKEN_NEW_KEYINFO);
                String newKeyInfoMap = "tks." + keySet + ".mk_mappings." + temp;
                String newMappingValue = config.getString(newKeyInfoMap, null);
                if (newMappingValue != null) {
                    StringTokenizer st = new StringTokenizer(newMappingValue, ":");
                    int tokenNumber = 0;
                    while (st.hasMoreTokens()) {
                        String currentToken = st.nextToken();
                        if (tokenNumber == 1)
                            mNewKeyNickName = currentToken;
                        tokenNumber++;
                    }
                }
            }

            SecureChannelProtocol.setDefaultPrefix(masterKeyPrefix);

        } catch (Exception e) {
            logger.debug("TKSTokenResource.setDefaultSlotAndKeyName: Exception: {}", e.toString());
        }
    }

    /**
     * Reads the nistSP800-108KdfOnKeyVersion configuration value for the given key set.
     */
    private static byte readNistSP800_108KdfOnKeyVersion(String keySet) throws Exception {
        String settingMap = "tks." + keySet + ".nistSP800-108KdfOnKeyVersion";
        TKSEngine engine = TKSEngine.getInstance();
        TKSEngineConfig config = engine.getConfig();
        String settingValue = config.getString(settingMap, "00");

        if (settingValue == null) {
            throw new Exception("Required configuration value \"" + settingMap + "\" missing.");
        }

        try {
            short shortValue = Short.parseShort(settingValue, 16);
            if (shortValue < 0 || shortValue > (short) 0x00FF) {
                throw new Exception("Out of range.");
            }
            return (byte) shortValue;
        } catch (Throwable t) {
            throw new Exception("Configuration value \"" + settingMap + "\" is in incorrect format.", t);
        }
    }

    /**
     * Reads the nistSP800-108KdfUseCuidAsKdd configuration value for the given key set.
     */
    private static boolean readNistSP800_108KdfUseCuidAsKdd(String keySet) throws Exception {
        String settingMap = "tks." + keySet + ".nistSP800-108KdfUseCuidAsKdd";
        TKSEngine engine = TKSEngine.getInstance();
        TKSEngineConfig config = engine.getConfig();
        String settingStr = config.getString(settingMap, "false");

        if (settingStr == null) {
            throw new Exception("Required configuration value \"" + settingMap + "\" missing.");
        }

        return Boolean.parseBoolean(settingStr);
    }

    /**
     * Returns the shared secret name from the TKS configuration.
     * Supports both legacy and new shared secret naming schemes.
     */
    private String getSharedSecretName(ConfigStore cs) throws EBaseException {
        boolean useNewNames = cs.getBoolean("tks.useNewSharedSecretNames", false);

        if (useNewNames) {
            String tpsList = cs.getString("tps.list", "");
            String firstSharedSecretName = null;
            if (!tpsList.isEmpty()) {
                for (String tpsID : tpsList.split(",")) {
                    String sharedSecretName = cs.getString("tps." + tpsID + ".nickname", "");
                    if (firstSharedSecretName == null) {
                        firstSharedSecretName = sharedSecretName;
                    }
                    if (!sharedSecretName.isEmpty() && mCurrentUID != null) {
                        String csUid = cs.getString("tps." + tpsID + ".userid", "");
                        if (mCurrentUID.equalsIgnoreCase(csUid)) {
                            return sharedSecretName;
                        }
                    }
                }
                if (firstSharedSecretName != null) {
                    return firstSharedSecretName;
                }
            }
            throw new EBaseException("No shared secret has been configured");
        }

        return cs.getString("tks.tksSharedSymKeyName", TRANSPORT_KEY_NAME);
    }

    /**
     * Retrieves the shared secret symmetric key from the NSS database.
     */
    private PK11SymKey getSharedSecretKey(ConfigStore cs) throws EBaseException {
        String sharedSecretName;
        try {
            sharedSecretName = getSharedSecretName(cs);
        } catch (EBaseException e) {
            throw new EBaseException("Internal error finding config value: " + e);
        }

        String symmKeys = null;
        boolean keyPresent = false;
        try {
            symmKeys = SessionKey.ListSymmetricKeys(CryptoUtil.INTERNAL_TOKEN_NAME);
        } catch (Exception e) {
            logger.debug("TKSTokenResource.getSharedSecretKey: {}", e.toString());
        }

        if (symmKeys != null) {
            for (String keyName : symmKeys.split(",")) {
                if (sharedSecretName.equals(keyName)) {
                    keyPresent = true;
                    break;
                }
            }
        }

        if (!keyPresent) {
            throw new EBaseException("Can't find shared secret!");
        }

        String tokenName = CryptoUtil.INTERNAL_TOKEN_FULL_NAME;
        return SessionKey.GetSymKeyByName(tokenName, sharedSecretName);
    }

    /**
     * Reads GP (Global Platform) settings for SCP03 from the TKS configuration.
     */
    private static GPParams readGPSettings(String keySet) {
        GPParams params = new GPParams();
        String gp3Settings = "tks." + keySet + ".prot3";

        TKSEngine engine = TKSEngine.getInstance();
        TKSEngineConfig sconfig = engine.getConfig();

        String divers = "emv";
        try {
            divers = sconfig.getString(gp3Settings + ".divers", "emv");
        } catch (EBaseException e) {
            // use default
        }
        params.setDiversificationScheme(divers);

        String diversVer1Keys = "emv";
        try {
            diversVer1Keys = sconfig.getString(gp3Settings + ".diversVer1Keys", "emv");
        } catch (EBaseException e) {
            // use default
        }
        params.setVersion1DiversificationScheme(diversVer1Keys);

        String keyType = null;
        try {
            keyType = sconfig.getString(gp3Settings + ".devKeyType", "DES3");
        } catch (EBaseException e) {
            // use default
        }
        params.setDevKeyType(keyType);

        try {
            keyType = sconfig.getString(gp3Settings + ".masterKeyType", "DES3");
        } catch (EBaseException e) {
            // use default
        }
        params.setMasterKeyType(keyType);

        return params;
    }

    /**
     * Reads a developer key array from the TKS configuration.
     */
    private byte[] getDevKeyArray(String keyType, ConfigStore sconfig, String keySet) throws EBaseException {
        try {
            return org.mozilla.jss.netscape.security.util.Utils.SpecialDecode(
                    sconfig.getString("tks." + keySet + "." + keyType));
        } catch (Exception e) {
            throw new EBaseException("Can't read static developer key array: " + keySet + ": " + keyType);
        }
    }

    /**
     * Calculates server-side keygen values for SCP03.
     *
     * Returns ArrayList of:
     *   0: kek_wrapped_desKey
     *   1: keycheck_des
     *   2: keycheck_aes
     *   3: drm_trans_desKey
     *   4: drm_trans_aesKey
     *   5: kek_wrapped_aesKey
     */
    private ArrayList<String> calculateServerSideKeygenValues(
            String useSoftToken, String selectedToken,
            SymmetricKey kekSessionKey, SecureChannelProtocol protocol,
            TKSEngineConfig sconfig) throws EBaseException {

        String method = "TKSTokenResource.calculateServerSideKeygenValues:";
        ArrayList<String> values = new ArrayList<>();
        int protocolLevel = protocol.getProtocol();

        SymmetricKey desKey;
        SymmetricKey aesKey = null;

        if (useSoftToken.equals("true")) {
            desKey = protocol.generateSymKey("internal");
            if (protocolLevel == 3) {
                aesKey = protocol.generateAESSymKey("internal", 128);
            }
        } else {
            desKey = protocol.generateSymKey(selectedToken);
            if (protocolLevel == 3) {
                aesKey = protocol.generateAESSymKey(selectedToken, 128);
            }
        }

        if (desKey == null && protocolLevel == 1) {
            throw new EBaseException(method + " can't generate DES key");
        }
        if (aesKey == null && protocolLevel == 3) {
            throw new EBaseException(method + " can't generate AES key");
        }

        byte[] encDesKey = protocol.ecbEncrypt(kekSessionKey, desKey, selectedToken);
        byte[] encAesKey = protocol.ecbEncrypt(kekSessionKey, aesKey, selectedToken);

        values.add(org.mozilla.jss.netscape.security.util.Utils.SpecialEncode(encDesKey)); // 0: kek_wrapped_desKey

        byte[] keycheck = protocol.computeKeyCheck(desKey, selectedToken);
        byte[] keycheck_aes = null;
        if (aesKey != null) {
            keycheck_aes = protocol.computeKeyCheck_SCP03(aesKey, selectedToken);
        }

        values.add(keycheck != null ? org.mozilla.jss.netscape.security.util.Utils.SpecialEncode(keycheck) : ""); // 1: keycheck_des
        values.add(keycheck_aes != null ? org.mozilla.jss.netscape.security.util.Utils.SpecialEncode(keycheck_aes) : ""); // 2: keycheck_aes

        // Wrap with DRM transport cert
        String drmTransNickname = sconfig.getString("tks.drm_transport_cert_nickname", "");
        if (isNullOrEmpty(drmTransNickname)) {
            throw new EBaseException(method + " can't find DRM transport certificate nickname");
        }

        try {
            X509Certificate drmTransCert = CryptoManager.getInstance().findCertByNickname(drmTransNickname);
            CryptoToken token;
            if (useSoftToken.equals("true")) {
                token = CryptoManager.getInstance().getInternalCryptoToken();
            } else {
                token = CryptoManager.getInstance().getTokenByName(selectedToken);
            }

            PublicKey pubKey = drmTransCert.getPublicKey();
            String pubKeyAlgo = pubKey.getAlgorithm();

            KeyWrapper keyWrapper;
            if (pubKeyAlgo.equals("EC")) {
                keyWrapper = token.getKeyWrapper(KeyWrapAlgorithm.AES_ECB);
                keyWrapper.initWrap(pubKey, null);
            } else {
                boolean useOAEP = sconfig.getBoolean("keyWrap.useOAEP", false);
                KeyWrapAlgorithm wrapAlg = useOAEP ? KeyWrapAlgorithm.RSA_OAEP : KeyWrapAlgorithm.RSA;
                keyWrapper = token.getKeyWrapper(wrapAlg);
                OAEPParameterSpec params = null;
                if (useOAEP) {
                    params = new OAEPParameterSpec("SHA-256", "MGF1",
                            MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
                }
                keyWrapper.initWrap(pubKey, params);
            }

            byte[] wrappedDesKey = keyWrapper.wrap(desKey);
            values.add(org.mozilla.jss.netscape.security.util.Utils.SpecialEncode(wrappedDesKey)); // 3: drm_trans_desKey

            if (aesKey != null) {
                byte[] wrappedAesKey = keyWrapper.wrap(aesKey);
                values.add(org.mozilla.jss.netscape.security.util.Utils.SpecialEncode(wrappedAesKey)); // 4: drm_trans_aesKey
            }

            // kek wrapped aes key
            values.add(org.mozilla.jss.netscape.security.util.Utils.SpecialEncode(encAesKey)); // 5: kek_wrapped_aesKey

        } catch (Exception e) {
            throw new EBaseException(method + " Exception wrapping keys: " + e.toString(), e);
        }

        return values;
    }

    /**
     * Compares two cryptograms for equality.
     */
    private boolean cryptogramsAreEqual(byte[] original, byte[] calculated) {
        if (original == null || calculated == null) {
            return false;
        }
        if (original.length != calculated.length) {
            return false;
        }
        for (int i = 0; i < original.length; i++) {
            if (original[i] != calculated[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * Returns the current agent ID from the session context.
     */
    private String getAgentId() {
        SessionContext sContext = SessionContext.getContext();
        String agentId = "";
        if (sContext != null) {
            agentId = (String) sContext.get(SessionContext.USER_ID);
        }
        return agentId != null ? agentId : "";
    }

    /**
     * Converts a byte array to an ASCII-hex string for audit logging.
     * Returns "null" if the input is null.
     */
    private String logBytesToHex(byte[] bytes) {
        if (bytes == null) {
            return "null";
        }
        return bytesToHex(bytes);
    }

    /**
     * Converts a byte array to an uppercase hex string without separators.
     */
    private String bytesToHex(byte[] bytes) {
        char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int thisChar = bytes[i] & 0x000000FF;
            hexChars[i * 2] = hexArray[thisChar >>> 4];
            hexChars[i * 2 + 1] = hexArray[thisChar & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * Safely converts a keyInfo byte array to a hex version string for logging.
     */
    private String logKeyInfoVersion(byte[] xkeyInfo) {
        if (xkeyInfo == null) return "null";
        if (xkeyInfo.length < 1) return "invalid";
        return "0x" + Integer.toHexString(xkeyInfo[0] & 0x000000FF);
    }

    /**
     * Returns a human-readable error message for the given status code.
     */
    private String getErrorMessage(String status, String badParams) {
        switch (status) {
            case "1":
                return "Problem generating session key info.";
            case "2":
                return "Problem creating host_cryptogram.";
            case "3":
                if (badParams.endsWith(",")) {
                    badParams = badParams.substring(0, badParams.length() - 1);
                }
                return "Missing input parameters :" + badParams;
            case "4":
                return "Problem obtaining token information.";
            case "5":
                return "Card cryptogram mismatch. Token likely has incorrect keys.";
            case "6":
                return "Problem reading required configuration value.";
            default:
                return "Unknown error.";
        }
    }

    /**
     * Removes newline characters from a string (utility for log formatting).
     */
    private static String trim(String a) {
        StringBuilder newa = new StringBuilder();
        StringTokenizer tokens = new StringTokenizer(a, "\n");
        while (tokens.hasMoreTokens()) {
            newa.append(tokens.nextToken());
        }
        return newa.toString();
    }

    /**
     * Checks if a string is null or empty.
     */
    private static boolean isNullOrEmpty(String s) {
        return s == null || s.isEmpty();
    }

    /**
     * Logs an audit message through the TKS auditor.
     */
    private void audit(String msg) {
        TKSEngine engine = engineQuarkus.getEngine();
        Auditor auditor = engine.getAuditor();
        auditor.log(msg);
    }
}
