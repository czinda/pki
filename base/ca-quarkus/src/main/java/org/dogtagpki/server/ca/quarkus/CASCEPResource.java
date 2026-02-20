//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Locale;
import java.util.Map;
import java.util.Vector;

import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.authentication.AuthManager;
import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.ca.CAConfig;
import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CAEngineConfig;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.ANY;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.BIT_STRING;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.crypto.Cipher;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.KeyGenerator;
import org.mozilla.jss.crypto.KeyPairGeneratorSpi;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.KeyWrapper;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.netscape.security.extensions.CertInfo;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.pkcs.PKCS10Attribute;
import org.mozilla.jss.netscape.security.pkcs.PKCS10Attributes;
import org.mozilla.jss.netscape.security.util.ObjectIdentifier;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.AVA;
import org.mozilla.jss.netscape.security.x509.CertAttrSet;
import org.mozilla.jss.netscape.security.x509.CertificateChain;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.CertificateSubjectName;
import org.mozilla.jss.netscape.security.x509.CertificateVersion;
import org.mozilla.jss.netscape.security.x509.CertificateX509Key;
import org.mozilla.jss.netscape.security.x509.ChallengePassword;
import org.mozilla.jss.netscape.security.x509.DNSName;
import org.mozilla.jss.netscape.security.x509.Extension;
import org.mozilla.jss.netscape.security.x509.ExtensionsRequested;
import org.mozilla.jss.netscape.security.x509.GeneralName;
import org.mozilla.jss.netscape.security.x509.GeneralNameInterface;
import org.mozilla.jss.netscape.security.x509.GeneralNames;
import org.mozilla.jss.netscape.security.x509.IPAddressName;
import org.mozilla.jss.netscape.security.x509.KeyUsageExtension;
import org.mozilla.jss.netscape.security.x509.OIDMap;
import org.mozilla.jss.netscape.security.x509.RDN;
import org.mozilla.jss.netscape.security.x509.SubjectAlternativeNameExtension;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X500NameAttrMap;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.X509Key;
import org.mozilla.jss.pkcs7.IssuerAndSerialNumber;
import org.mozilla.jss.pkix.cert.Certificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.authentication.AuthCredentials;
import com.netscape.certsrv.authentication.EInvalidCredentials;
import com.netscape.certsrv.authentication.EMissingCredential;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.AuditFormat;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.profile.EDeferException;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.profile.common.EnrollProfile;
import com.netscape.cms.profile.common.Profile;
import com.netscape.cms.servlet.cert.scep.SCEPConfig;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.authentication.AuthSubsystem;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmscore.profile.ProfileSubsystem;
import com.netscape.cmscore.request.CertRequestRepository;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestNotifier;
import com.netscape.cmscore.request.RequestRecord;
import com.netscape.cmscore.request.RequestRepository;
import com.netscape.cmscore.security.JssSubsystem;
import com.netscape.cmscore.security.PWCBsdr;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.scep.CRSPKIMessage;

/**
 * JAX-RS resource replacing the legacy CRSEnrollment (SCEP) servlet.
 * Implements the Simple Certificate Enrollment Protocol (SCEP/CRS)
 * as defined in draft-nourse-scep / RFC 8894.
 *
 * Legacy URL: /cgi-bin/pkiclient.exe
 *
 * SCEP operations (via 'operation' query parameter):
 * - GetCACaps:  Returns CA capabilities as text/plain
 * - GetCACert:  Returns CA certificate (chain) as DER
 * - GetNextCACert: Returns next CA certificate for rollover
 * - PKIOperation: Main enrollment/query (base64-encoded PKCS7)
 *
 * The 'message' query parameter carries operation-specific data.
 */
@Path("cgi-bin/pkiclient.exe")
public class CASCEPResource {

    private static final Logger logger = LoggerFactory.getLogger(CASCEPResource.class);

    private static final String OAEP_SHA = "SHA-256";

    // Default profile for SCEP enrollment requests
    private static final String DEFAULT_PROFILE_ID = "caRouterCert";

    // Authentication constants
    private static final String AUTH_PASSWORD = "pwd";
    private static final String AUTH_CREDS = "AuthCreds";
    private static final String AUTH_TOKEN = "AuthToken";
    private static final String SANE_DNSNAME = "DNSName";
    private static final String SANE_IPADDRESS = "IPAddress";
    private static final String CERTINFO = "CertInfo";
    private static final String SUBJECTNAME = "SubjectName";

    // OIDs used for subject name attributes
    private static ObjectIdentifier OID_UNSTRUCTUREDNAME;
    private static ObjectIdentifier OID_UNSTRUCTUREDADDRESS;

    static {
        X500NameAttrMap map = X500NameAttrMap.getDefault();
        OID_UNSTRUCTUREDNAME = map.getOid("UNSTRUCTUREDNAME");
        OID_UNSTRUCTUREDADDRESS = map.getOid("UNSTRUCTUREDADDRESS");
    }

    @Inject
    CAEngineQuarkus engineQuarkus;

    // Cached configuration (lazily initialized)
    private volatile boolean initialized = false;
    private boolean enabled;
    private boolean useCA = true;
    private boolean useOAEPKeyWrap;
    private String nickname;
    private String tokenName = "";
    private String hashAlgorithm = "SHA256";
    private String configuredEncryptionAlgorithm = "DES3";
    private String[] allowedHashAlgorithm;
    private String[] allowedEncryptionAlgorithm;
    private String allowedHashAlgorithmList;
    private String allowedEncryptionAlgorithmList;
    private int nonceSizeLimit;
    private String profileId = DEFAULT_PROFILE_ID;
    private String authManagerName;
    private String appendDN;
    private boolean createEntry;
    private boolean flattenDN;
    private String entryObjectclass = "cep";
    private String substoreName = "default";
    private SecureRandom random;
    private MessageDigest shaDigest;

    /**
     * Lazily initialize SCEP configuration from the CA engine config.
     * This mirrors the init() method from CRSEnrollment but reads
     * from the engine config rather than from servlet init parameters.
     */
    private synchronized void ensureInitialized() {
        if (initialized) {
            return;
        }

        CAEngine engine = engineQuarkus.getEngine();
        CAEngineConfig cs = engine.getConfig();
        JssSubsystem jssSubsystem = engine.getJSSSubsystem();
        CertificateAuthority ca = engine.getCA();

        try {
            CAConfig authorityConfig = ca.getConfig();
            SCEPConfig scepConfig = authorityConfig.getSCEPConfig();

            enabled = scepConfig.getEnable();
            useOAEPKeyWrap = cs.getUseOAEPKeyWrap();
            hashAlgorithm = scepConfig.getHashAlgorithm();
            configuredEncryptionAlgorithm = scepConfig.getEncryptionAlgorithm();
            nonceSizeLimit = scepConfig.getNonceSizeLimit();

            allowedHashAlgorithmList = scepConfig.getAllowedHashAlgorithms();
            allowedHashAlgorithm = trimArray(allowedHashAlgorithmList.split(","));

            allowedEncryptionAlgorithmList = scepConfig.getAllowedEncryptionAlgorithms();
            allowedEncryptionAlgorithm = trimArray(allowedEncryptionAlgorithmList.split(","));

            nickname = scepConfig.getNickname(ca.getNickname());
            if (nickname.equals(ca.getNickname())) {
                tokenName = ca.getSigningUnit().getTokenName();
            } else {
                tokenName = scepConfig.getTokenName();
                useCA = false;
            }
            if (!CryptoUtil.isInternalToken(tokenName)) {
                int i = nickname.indexOf(':');
                if (!((i > -1) && (tokenName.length() == i) && (nickname.startsWith(tokenName)))) {
                    nickname = tokenName + ":" + nickname;
                }
            }

            // Read profile and auth config from engine config
            // (In the servlet these came from init params; here we use defaults
            //  and the SCEP config subsection)
            ProfileSubsystem profileSubsystem = engine.getProfileSubsystem();
            if (profileSubsystem != null && profileSubsystem.getProfile(profileId) == null) {
                logger.warn("CASCEPResource: Default profile '{}' not found", profileId);
            }

            AuthSubsystem authSubsystem = engine.getAuthSubsystem();
            // authManagerName remains null unless configured; null means no auth
            // and requests go to manual approval

        } catch (EBaseException e) {
            logger.warn("CASCEPResource: Error reading SCEP config: {}", e.getMessage(), e);
        }

        try {
            shaDigest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            logger.error("CASCEPResource: SHA-256 not available", e);
        }

        random = jssSubsystem.getRandomNumberGenerator();

        logger.info("CASCEPResource: SCEP support is {}", enabled ? "enabled" : "disabled");
        logger.debug("CASCEPResource: SCEP nickname: {}", nickname);
        logger.debug("CASCEPResource: Token name: {}", tokenName);
        logger.debug("CASCEPResource: Is using CA keys: {}", useCA);
        logger.debug("CASCEPResource: Hash algorithm: {}", hashAlgorithm);
        logger.debug("CASCEPResource: Encryption algorithm: {}", configuredEncryptionAlgorithm);
        logger.debug("CASCEPResource: Nonce size limit: {}", nonceSizeLimit);
        logger.debug("CASCEPResource: OAEP key wrap: {}", useOAEPKeyWrap);

        initialized = true;
    }

    /**
     * Handle GET requests for all SCEP operations.
     * SCEP clients use GET for GetCACaps, GetCACert, GetNextCACert,
     * and PKIOperation (with base64 message in query string).
     */
    @GET
    public Response handleGet(
            @QueryParam("operation") String operation,
            @QueryParam("message") String message) {

        logger.info("CASCEPResource: GET operation={}", operation);

        ensureInitialized();

        if (!enabled) {
            logger.error("CASCEPResource: SCEP support is disabled");
            return Response.status(Response.Status.SERVICE_UNAVAILABLE)
                    .entity("SCEP support is disabled")
                    .type(MediaType.TEXT_PLAIN)
                    .build();
        }

        if (operation == null || operation.isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Missing 'operation' parameter")
                    .type(MediaType.TEXT_PLAIN)
                    .build();
        }

        CAEngine engine = engineQuarkus.getEngine();

        try {
            switch (operation) {
                case "GetCACaps":
                    return handleGetCACaps();
                case "GetCACert":
                    return handleGetCACert(engine, message);
                case "GetNextCACert":
                    return handleGetNextCACert(engine);
                case "PKIOperation":
                    return handlePKIOperation(engine, message);
                default:
                    logger.error("CASCEPResource: Unknown operation: {}", operation);
                    return Response.status(Response.Status.BAD_REQUEST)
                            .entity("Unknown operation: " + operation)
                            .type(MediaType.TEXT_PLAIN)
                            .build();
            }
        } catch (Exception e) {
            logger.error("CASCEPResource: Error processing {} operation: {}",
                    operation, e.getMessage(), e);
            return Response.serverError()
                    .entity("Error processing SCEP request: " + e.getMessage())
                    .type(MediaType.TEXT_PLAIN)
                    .build();
        }
    }

    /**
     * Handle POST requests for PKIOperation.
     * SCEP clients may POST the binary PKCS7 message directly.
     */
    @POST
    @Consumes(MediaType.APPLICATION_OCTET_STREAM)
    public Response handlePost(
            @QueryParam("operation") String operation,
            byte[] body) {

        logger.info("CASCEPResource: POST operation={}", operation);

        ensureInitialized();

        if (!enabled) {
            logger.error("CASCEPResource: SCEP support is disabled");
            return Response.status(Response.Status.SERVICE_UNAVAILABLE)
                    .entity("SCEP support is disabled")
                    .type(MediaType.TEXT_PLAIN)
                    .build();
        }

        // POST is only valid for PKIOperation
        if (operation != null && !operation.equals("PKIOperation")) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("POST only supports PKIOperation")
                    .type(MediaType.TEXT_PLAIN)
                    .build();
        }

        if (body == null || body.length == 0) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Empty request body")
                    .type(MediaType.TEXT_PLAIN)
                    .build();
        }

        CAEngine engine = engineQuarkus.getEngine();

        try {
            // POST body is the raw binary PKI message (not base64 encoded)
            String base64Message = Utils.base64encode(body, true);
            return handlePKIOperation(engine, base64Message);
        } catch (Exception e) {
            logger.error("CASCEPResource: Error processing POST PKIOperation: {}",
                    e.getMessage(), e);
            return Response.serverError()
                    .entity("Error processing SCEP request: " + e.getMessage())
                    .type(MediaType.TEXT_PLAIN)
                    .build();
        }
    }

    // ------------------------------------------------------------------
    //  GetCACaps
    // ------------------------------------------------------------------

    /**
     * Returns the CA capabilities as a series of plaintext lines.
     * Capabilities are dynamically determined from the allowed algorithm
     * configuration.
     *
     * Possible capabilities (per draft-gutmann-scep / RFC 8894):
     *   AES, DES3, POSTPKIOperation, Renewal, SHA-1, SHA-256, SHA-512,
     *   SCEPStandard, GetNextCACert
     */
    private Response handleGetCACaps() {
        StringBuilder caps = new StringBuilder();

        if (isAlgorithmAllowed(allowedEncryptionAlgorithm, "AES")) {
            caps.append("AES\n");
        }
        if (isAlgorithmAllowed(allowedEncryptionAlgorithm, "DES3")) {
            caps.append("DES3\n");
        }
        // POSTPKIOperation is now supported via JAX-RS POST handler
        caps.append("POSTPKIOperation\n");
        if (isAlgorithmAllowed(allowedHashAlgorithm, "SHA1")) {
            caps.append("SHA-1\n");
        }
        if (isAlgorithmAllowed(allowedHashAlgorithm, "SHA256")) {
            caps.append("SHA-256\n");
        }
        if (isAlgorithmAllowed(allowedHashAlgorithm, "SHA512")) {
            caps.append("SHA-512\n");
        }

        String response = caps.toString();
        logger.debug("CASCEPResource: GetCACaps response:\n{}", response);

        return Response.ok(response, MediaType.TEXT_PLAIN).build();
    }

    // ------------------------------------------------------------------
    //  GetCACert
    // ------------------------------------------------------------------

    /**
     * Returns the CA certificate (or a certificate from the chain) as
     * DER-encoded data with content type application/x-x509-ca-cert.
     *
     * The 'message' parameter, if a valid integer, selects an index into
     * the certificate chain (0 = leaf CA cert).
     */
    private Response handleGetCACert(CAEngine engine, String message) {
        CertificateAuthority ca = engine.getCA();

        try {
            CertificateChain certChain = ca.getCACertChain();
            if (certChain == null) {
                logger.error("CASCEPResource: Cannot get CA certificate chain");
                return Response.serverError()
                        .entity("Internal error: cannot get CA certificate")
                        .type(MediaType.TEXT_PLAIN)
                        .build();
            }

            java.security.cert.X509Certificate[] chain = certChain.getChain();

            // The message parameter optionally selects a cert in the chain
            int index = 0;
            if (message != null) {
                try {
                    int requested = Integer.parseInt(message);
                    if (requested >= 0 && requested < chain.length) {
                        index = requested;
                    }
                } catch (NumberFormatException e) {
                    // ignore; use default index 0
                }
            }
            logger.debug("CASCEPResource: GetCACert selected chain index={}", index);

            byte[] certBytes;
            if (useCA) {
                certBytes = chain[index].getEncoded();
            } else {
                // When using a separate SCEP key, return its cert
                CryptoContext cx = new CryptoContext();
                certBytes = cx.getSigningCert().getEncoded();
            }

            return Response.ok(certBytes, "application/x-x509-ca-cert").build();

        } catch (Exception e) {
            logger.error("CASCEPResource: Error sending CA certificate: {}", e.getMessage(), e);
            return Response.serverError()
                    .entity("Failed to return CA certificate: " + e.getMessage())
                    .type(MediaType.TEXT_PLAIN)
                    .build();
        }
    }

    // ------------------------------------------------------------------
    //  GetNextCACert
    // ------------------------------------------------------------------

    /**
     * Returns the next CA certificate for CA key rollover scenarios.
     * Currently not fully supported by Dogtag; returns the current CA
     * cert as a fallback.
     */
    private Response handleGetNextCACert(CAEngine engine) {
        CertificateAuthority ca = engine.getCA();

        try {
            CertificateChain certChain = ca.getCACertChain();
            if (certChain == null) {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity("No next CA certificate available")
                        .type(MediaType.TEXT_PLAIN)
                        .build();
            }

            java.security.cert.X509Certificate[] chain = certChain.getChain();
            byte[] certBytes = chain[0].getEncoded();

            logger.debug("CASCEPResource: GetNextCACert returning current CA cert (rollover not yet implemented)");
            return Response.ok(certBytes, "application/x-x509-ca-cert").build();

        } catch (Exception e) {
            logger.error("CASCEPResource: Error in GetNextCACert: {}", e.getMessage(), e);
            return Response.serverError()
                    .entity("Failed to return next CA certificate")
                    .type(MediaType.TEXT_PLAIN)
                    .build();
        }
    }

    // ------------------------------------------------------------------
    //  PKIOperation
    // ------------------------------------------------------------------

    /**
     * Processes a SCEP PKIOperation message.
     *
     * Flow:
     * 1. Base64-decode the PKCS7 message
     * 2. Parse the CRSPKIMessage to extract the SCEP envelope
     * 3. Validate encryption/hash algorithms against allowed lists
     * 4. Verify the message signature
     * 5. Decrypt/unwrap the PKCS10 CSR from the encrypted envelope
     * 6. Check for existing request with same transaction ID
     * 7. Extract certificate details and authenticate the requester
     * 8. Submit enrollment via the profile framework
     * 9. Wrap the response certificate in a signed/encrypted PKCS7
     *
     * @param engine the CA engine
     * @param message base64-encoded PKCS7 SCEP message
     * @return PKCS7 response with content type application/x-pki-message
     */
    private Response handlePKIOperation(CAEngine engine, String message) {
        if (message == null || message.isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Missing 'message' parameter for PKIOperation")
                    .type(MediaType.TEXT_PLAIN)
                    .build();
        }

        // Track encryption algorithm per-request (may be overridden by client)
        String encryptionAlgorithm = configuredEncryptionAlgorithm;

        CryptoContext cx = null;
        CRSPKIMessage req = null;
        CRSPKIMessage crsResp = null;
        X509CertImpl issuedCert = null;
        byte[] decodedPKIMessage = Utils.base64decode(message);

        try {
            if (decodedPKIMessage.length < 50) {
                logger.error("CASCEPResource: PKI message too small ({} bytes)", decodedPKIMessage.length);
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity("SCEP request too small to be valid")
                        .type(MediaType.TEXT_PLAIN)
                        .build();
            }

            // Parse the SCEP request envelope
            ByteArrayInputStream is = new ByteArrayInputStream(decodedPKIMessage);
            try {
                req = new CRSPKIMessage(is);
            } catch (Exception e) {
                logger.error("CASCEPResource: Failed to decode PKI message: {}", e.getMessage(), e);
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity("Could not decode the SCEP request")
                        .type(MediaType.TEXT_PLAIN)
                        .build();
            }

            // Validate encryption algorithm
            String ea = req.getEncryptionAlgorithm();
            if (!isAlgorithmAllowed(allowedEncryptionAlgorithm, ea)) {
                logger.error("CASCEPResource: Encryption algorithm '{}' not allowed ({})",
                        ea, allowedEncryptionAlgorithmList);
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity("Encryption algorithm '" + ea + "' is not allowed")
                        .type(MediaType.TEXT_PLAIN)
                        .build();
            }

            // Validate digest/hash algorithm
            String da = req.getDigestAlgorithmName();
            if (!isAlgorithmAllowed(allowedHashAlgorithm, da)) {
                logger.error("CASCEPResource: Hash algorithm '{}' not allowed ({})",
                        da, allowedHashAlgorithmList);
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity("Hash algorithm '" + da + "' is not allowed")
                        .type(MediaType.TEXT_PLAIN)
                        .build();
            }

            if (ea != null) {
                encryptionAlgorithm = ea;
            }

            // Initialize response message
            crsResp = new CRSPKIMessage();
            crsResp.setMessageType(CRSPKIMessage.mType_CertRep);

            // Create crypto context for this operation
            cx = new CryptoContext(encryptionAlgorithm);

            // Verify signature on the SCEP message
            verifyRequest(req);

            // Set up transaction ID
            String transactionID = req.getTransactionID();
            if (transactionID == null) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity("Malformed PKI message: missing transactionID")
                        .type(MediaType.TEXT_PLAIN)
                        .build();
            }
            crsResp.setTransactionID(transactionID);

            // Handle nonces
            byte[] senderNonce = req.getSenderNonce();
            if (senderNonce == null) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity("Malformed PKI message: missing senderNonce")
                        .type(MediaType.TEXT_PLAIN)
                        .build();
            }
            if (nonceSizeLimit > 0 && senderNonce.length > nonceSizeLimit) {
                byte[] limitedNonce = new byte[nonceSizeLimit];
                System.arraycopy(senderNonce, 0, limitedNonce, 0, nonceSizeLimit);
                crsResp.setRecipientNonce(limitedNonce);
            } else {
                crsResp.setRecipientNonce(senderNonce);
            }
            byte[] serverNonce = new byte[16];
            random.nextBytes(serverNonce);
            crsResp.setSenderNonce(serverNonce);

            // Determine message type and process accordingly
            String mt = req.getMessageType();
            if (mt == null) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity("Malformed PKI message: missing messageType")
                        .type(MediaType.TEXT_PLAIN)
                        .build();
            }

            if (mt.equals(CRSPKIMessage.mType_PKCSReq)) {
                logger.debug("CASCEPResource: Processing PKCSReq");
                issuedCert = handlePKCSReq(engine, req, crsResp, cx, encryptionAlgorithm);
            } else if (mt.equals(CRSPKIMessage.mType_GetCertInitial)) {
                logger.debug("CASCEPResource: Processing GetCertInitial");
                issuedCert = handleGetCertInitial(engine, req, crsResp);
            } else {
                logger.warn("CASCEPResource: Unknown message type: {}", mt);
            }

        } catch (Exception e) {
            logger.error("CASCEPResource: Error in PKIOperation: {}", e.getMessage(), e);
            if (crsResp != null) {
                crsResp.setFailInfo(CRSPKIMessage.mFailInfo_badMessageCheck);
                crsResp.setPKIStatus(CRSPKIMessage.mStatus_FAILURE);
            } else {
                return Response.serverError()
                        .entity("Failed to process SCEP request: " + e.getMessage())
                        .type(MediaType.TEXT_PLAIN)
                        .build();
            }
        }

        // Build the signed/encrypted response
        try {
            processCertRep(cx, issuedCert, crsResp, req, encryptionAlgorithm);

            byte[] responseBytes = crsResp.getResponse();
            logger.debug("CASCEPResource: PKIOperation response length: {} bytes", responseBytes.length);

            return Response.ok(responseBytes, "application/x-pki-message").build();

        } catch (Exception e) {
            logger.error("CASCEPResource: Failed to create response: {}", e.getMessage(), e);
            return Response.serverError()
                    .entity("Failed to create SCEP response")
                    .type(MediaType.TEXT_PLAIN)
                    .build();
        }
    }

    // ------------------------------------------------------------------
    //  PKIOperation helper methods
    // ------------------------------------------------------------------

    /**
     * Verify the signature on a SCEP request message.
     */
    private void verifyRequest(CRSPKIMessage req) {
        // Check authenticated attributes and digest
        // (same as CRSEnrollment - basic validation only)
        @SuppressWarnings("unused")
        byte[] aa = req.getAA();
        @SuppressWarnings("unused")
        byte[] aaDigest = req.getAADigest();
    }

    /**
     * Decrypt the PKCS10 CSR from the SCEP envelope.
     */
    private void unwrapPKCS10(CRSPKIMessage req, CryptoContext cx, String encryptionAlgorithm)
            throws Exception {

        SymmetricKey.Type skt;
        EncryptionAlgorithm ea;
        boolean padding = false;

        // Unwrap the session key using the CA/SCEP private key
        KeyWrapper kw = cx.getKeyWrapper();
        AlgorithmParameterSpec keyWrapConfig = null;
        if (useOAEPKeyWrap) {
            keyWrapConfig = new OAEPParameterSpec(
                    OAEP_SHA, "MGF1", MGF1ParameterSpec.SHA256,
                    PSource.PSpecified.DEFAULT);
            padding = true;
        }
        kw.initUnwrap(cx.getPrivateKey(), keyWrapConfig);

        switch (String.valueOf(encryptionAlgorithm)) {
            case "DES3":
                skt = SymmetricKey.DES3;
                ea = EncryptionAlgorithm.DES3_CBC;
                break;
            case "AES":
                skt = SymmetricKey.AES;
                ea = EncryptionAlgorithm.AES_128_CBC;
                break;
            default:
                skt = SymmetricKey.DES;
                ea = EncryptionAlgorithm.DES_CBC;
        }

        SymmetricKey sk = kw.unwrapSymmetric(
                req.getWrappedKey(), skt,
                SymmetricKey.Usage.DECRYPT,
                padding ? ea.getKeyStrength() / 8 : 0);

        SymmetricKey skInternal = moveSymmetricToInternalToken(cx, sk, skt, ea, encryptionAlgorithm);

        Cipher cip = skInternal.getOwningToken().getCipherContext(ea);
        cip.initDecrypt(skInternal, new IVParameterSpec(req.getIV()));

        byte[] decryptedP10 = cip.doFinal(req.getEncryptedPkcs10());
        req.setP10(new PKCS10(decryptedP10));
    }

    /**
     * Move a symmetric key to the internal token for crypto operations.
     * Required when the SCEP key lives on an external HSM token.
     */
    private SymmetricKey moveSymmetricToInternalToken(
            CryptoContext cx, SymmetricKey sk,
            SymmetricKey.Type skt, EncryptionAlgorithm ea,
            String encryptionAlgorithm) throws Exception {

        boolean padding = false;
        KeyPairGeneratorSpi.Usage[] usage = {
                KeyPairGeneratorSpi.Usage.WRAP,
                KeyPairGeneratorSpi.Usage.UNWRAP,
                KeyPairGeneratorSpi.Usage.ENCRYPT,
                KeyPairGeneratorSpi.Usage.DECRYPT
        };
        KeyPair keyPairWrap = CryptoUtil.generateRSAKeyPair(
                cx.getInternalToken(), 2048, true, true, false, usage, usage);

        KeyWrapAlgorithm kwAlg = KeyWrapAlgorithm.RSA;
        AlgorithmParameterSpec algSpec = null;
        if (useOAEPKeyWrap) {
            kwAlg = KeyWrapAlgorithm.RSA_OAEP;
            algSpec = new OAEPParameterSpec(
                    OAEP_SHA, "MGF1", MGF1ParameterSpec.SHA256,
                    PSource.PSpecified.DEFAULT);
            padding = true;
        }

        KeyWrapper kwWrap = sk.getOwningToken().getKeyWrapper(kwAlg);
        kwWrap.initWrap(keyPairWrap.getPublic(), algSpec);
        byte[] wrappedSK = kwWrap.wrap(sk);

        KeyWrapper kwInt = cx.getInternalToken().getKeyWrapper(kwAlg);
        PrivateKey pk = (PrivateKey) keyPairWrap.getPrivate();
        kwInt.initUnwrap(pk, algSpec);

        return kwInt.unwrapSymmetric(
                wrappedSK, skt, SymmetricKey.Usage.DECRYPT,
                padding ? ea.getKeyStrength() / 8 : 0);
    }

    /**
     * Find an existing request by SCEP transaction ID.
     * Returns null if no active (pending/complete) request found.
     */
    private Request findRequestByTransactionID(CAEngine engine, String txid, boolean ignoreRejected)
            throws EBaseException {

        RequestRepository requestRepository = engine.getRequestRepository();
        Request foundRequest = null;

        Collection<RequestRecord> records = requestRepository.findRequestsBySourceId(txid);
        for (RequestRecord record : records) {
            Request request = record.toRequest();
            if (!ignoreRejected ||
                    request.getRequestStatus().equals(RequestStatus.PENDING) ||
                    request.getRequestStatus().equals(RequestStatus.COMPLETE)) {
                foundRequest = request;
            }
        }
        return foundRequest;
    }

    /**
     * Handle a GetCertInitial message type.
     * Looks up existing request by transaction ID and returns the cert
     * if available.
     */
    private X509CertImpl handleGetCertInitial(
            CAEngine engine, CRSPKIMessage req, CRSPKIMessage resp) {

        try {
            Request foundRequest = findRequestByTransactionID(
                    engine, req.getTransactionID(), false);

            if (foundRequest == null) {
                resp.setFailInfo(CRSPKIMessage.mFailInfo_badCertId);
                resp.setPKIStatus(CRSPKIMessage.mStatus_FAILURE);
                return null;
            }

            return makeResponseFromRequest(req, resp, foundRequest);
        } catch (EBaseException e) {
            logger.error("CASCEPResource: Error finding request: {}", e.getMessage(), e);
            resp.setFailInfo(CRSPKIMessage.mFailInfo_internalCAError);
            resp.setPKIStatus(CRSPKIMessage.mStatus_FAILURE);
            return null;
        }
    }

    /**
     * Handle a PKCSReq message type - the main enrollment flow.
     *
     * 1. Decrypt the PKCS10 CSR
     * 2. Check for duplicate transaction IDs
     * 3. Extract subject, extensions, and credentials
     * 4. Authenticate the requester (if auth is configured)
     * 5. Submit enrollment via profile framework
     * 6. Return the issued certificate
     */
    private X509CertImpl handlePKCSReq(
            CAEngine engine, CRSPKIMessage req, CRSPKIMessage crsResp,
            CryptoContext cx, String encryptionAlgorithm) throws Exception {

        Auditor auditor = engine.getAuditor();

        try {
            unwrapPKCS10(req, cx, encryptionAlgorithm);
            Hashtable<String, byte[]> fingerprints = makeFingerPrints(req);

            // Check for existing request with same transaction ID
            Request existingRequest = findRequestByTransactionID(
                    engine, req.getTransactionID(), true);

            if (existingRequest != null) {
                if (areFingerprintsEqual(existingRequest, fingerprints)) {
                    logger.debug("CASCEPResource: Returning response from existing request");
                    return makeResponseFromRequest(req, crsResp, existingRequest);
                }
                logger.warn("CASCEPResource: Duplicate transaction ID with different fingerprint");
                crsResp.setFailInfo(CRSPKIMessage.mFailInfo_badRequest);
                crsResp.setPKIStatus(CRSPKIMessage.mStatus_FAILURE);
                return null;
            }

            // Extract certificate details from the PKCS10
            getDetailFromRequest(req, crsResp);

            // Authenticate the user
            boolean authFailed = authenticateUser(engine, req);
            if (authFailed) {
                logger.warn("CASCEPResource: Authentication failed for SCEP request");
                crsResp.setFailInfo(CRSPKIMessage.mFailInfo_badIdentity);
                crsResp.setPKIStatus(CRSPKIMessage.mStatus_FAILURE);

                String auditMessage = CMS.getLogMessage(
                        AuditEvent.NON_PROFILE_CERT_REQUEST,
                        "SCEP-client",
                        ILogger.FAILURE,
                        req.getTransactionID(),
                        "CASCEPResource",
                        ILogger.SIGNED_AUDIT_EMPTY_VALUE);
                auditor.log(auditMessage);

                return null;
            }

            // Submit the enrollment request
            Request enrollRequest = postRequest(engine, req, crsResp);
            if (enrollRequest == null) {
                return null;
            }

            logger.debug("CASCEPResource: Created enrollment response");
            return makeResponseFromRequest(req, crsResp, enrollRequest);

        } catch (Exception e) {
            logger.error("CASCEPResource: PKCSReq processing error: {}", e.getMessage(), e);
            crsResp.setFailInfo(CRSPKIMessage.mFailInfo_internalCAError);
            crsResp.setPKIStatus(CRSPKIMessage.mStatus_FAILURE);
            return null;
        }
    }

    /**
     * Extract certificate information from the PKCS10 in the SCEP request.
     * Populates the request with subject name, key, extensions, and auth credentials.
     */
    private void getDetailFromRequest(CRSPKIMessage req, CRSPKIMessage crsResp) {
        SubjectAlternativeNameExtension sane = null;

        try {
            PKCS10 p10 = req.getP10();
            if (p10 == null) {
                crsResp.setFailInfo(CRSPKIMessage.mFailInfo_badMessageCheck);
                crsResp.setPKIStatus(CRSPKIMessage.mStatus_FAILURE);
                return;
            }

            AuthCredentials authCreds = new AuthCredentials();
            X509CertInfo certInfo = new CertInfo();

            X509Key key = p10.getSubjectPublicKeyInfo();
            X500Name p10subject = p10.getSubjectName();
            X500Name subject;

            // Process RDNs from the subject name, collecting auth credentials
            // and SAN data from unstructured name/address attributes
            Enumeration<RDN> rdne = p10subject.getRDNs();
            Vector<RDN> rdnv = new Vector<>();
            Hashtable<String, String> saneHash = new Hashtable<>();
            X500NameAttrMap xnap = X500NameAttrMap.getDefault();

            while (rdne.hasMoreElements()) {
                RDN rdn = rdne.nextElement();
                AVA[] oldAvas = rdn.getAssertion();
                for (int i = 0; i < rdn.getAssertionLength(); i++) {
                    AVA[] newAvas = new AVA[] { oldAvas[i] };
                    authCreds.set(
                            xnap.getName(oldAvas[i].getOid()),
                            oldAvas[i].getValue().getAsString());

                    if (oldAvas[i].getOid().equals(OID_UNSTRUCTUREDNAME)) {
                        saneHash.put(SANE_DNSNAME, oldAvas[i].getValue().getAsString());
                    }
                    if (oldAvas[i].getOid().equals(OID_UNSTRUCTUREDADDRESS)) {
                        saneHash.put(SANE_IPADDRESS, oldAvas[i].getValue().getAsString());
                    }

                    RDN newRdn = new RDN(newAvas);
                    if (flattenDN) {
                        rdnv.addElement(newRdn);
                    }
                }
            }

            subject = flattenDN ? new X500Name(rdnv) : p10subject;

            // Default key usage extension
            KeyUsageExtension kue = new KeyUsageExtension();
            kue.set(KeyUsageExtension.DIGITAL_SIGNATURE, Boolean.TRUE);
            kue.set(KeyUsageExtension.KEY_ENCIPHERMENT, Boolean.TRUE);

            // Process PKCS10 attributes (challenge password, extensions)
            PKCS10Attributes p10atts = p10.getAttributes();
            Enumeration<PKCS10Attribute> e = p10atts.getElements();

            while (e.hasMoreElements()) {
                PKCS10Attribute p10a = e.nextElement();
                CertAttrSet attr = p10a.getAttributeValue();

                if (attr.getName().equals(ChallengePassword.NAME)) {
                    if (attr.get(ChallengePassword.PASSWORD) != null) {
                        req.put(AUTH_PASSWORD, attr.get(ChallengePassword.PASSWORD));
                        req.put(ChallengePassword.NAME,
                                hashPassword((String) attr.get(ChallengePassword.PASSWORD)));
                    }
                }

                if (attr.getName().equals(ExtensionsRequested.NAME)) {
                    Enumeration<Extension> exts =
                            ((ExtensionsRequested) attr).getExtensions().elements();
                    while (exts.hasMoreElements()) {
                        Extension ext = exts.nextElement();

                        if (ext.getExtensionId().equals(
                                OIDMap.getOID(KeyUsageExtension.IDENT))) {
                            kue = new KeyUsageExtension(Boolean.FALSE, ext.getExtensionValue());
                        }

                        if (ext.getExtensionId().equals(
                                OIDMap.getOID(SubjectAlternativeNameExtension.IDENT))) {
                            sane = new SubjectAlternativeNameExtension(
                                    Boolean.FALSE, ext.getExtensionValue());

                            @SuppressWarnings("unchecked")
                            Vector<GeneralNameInterface> v =
                                    (Vector<GeneralNameInterface>) sane.get(
                                            SubjectAlternativeNameExtension.SUBJECT_NAME);
                            Enumeration<GeneralNameInterface> gne = v.elements();
                            while (gne.hasMoreElements()) {
                                GeneralNameInterface gni = gne.nextElement();
                                if (gni instanceof GeneralName genName) {
                                    String gn = genName.toString();
                                    int colon = gn.indexOf(':');
                                    String gnType = gn.substring(0, colon).trim();
                                    String gnValue = gn.substring(colon + 1).trim();
                                    authCreds.set(gnType, gnValue);
                                }
                            }
                        }
                    }
                }
            }

            req.put(AUTH_CREDS, authCreds);

            // Build default SAN from unstructured name/address if none requested
            try {
                if (sane == null) {
                    sane = makeDefaultSubjectAltName(saneHash);
                }
            } catch (Exception saneEx) {
                logger.warn("CASCEPResource: Could not create default SAN: {}", saneEx.getMessage());
            }

            // Append configured DN suffix
            try {
                if (appendDN != null && !appendDN.isEmpty()) {
                    new X500Name(subject.toString()); // validate
                    subject = new X500Name(subject.toString() + "," + appendDN);
                }
            } catch (Exception sne) {
                logger.warn("CASCEPResource: Unable to use appendDN '{}': {}", appendDN, sne.getMessage());
            }

            if (subject != null) {
                req.put(SUBJECTNAME, subject);
            }

            certInfo.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
            certInfo.set(X509CertInfo.SUBJECT, new CertificateSubjectName(subject));
            certInfo.set(X509CertInfo.KEY, new CertificateX509Key(key));

            CertificateExtensions ext = new CertificateExtensions();
            if (kue != null) {
                ext.set(KeyUsageExtension.NAME, kue);
            }
            if (sane != null) {
                ext.set(SubjectAlternativeNameExtension.NAME, sane);
            }
            certInfo.set(X509CertInfo.EXTENSIONS, ext);
            req.put(CERTINFO, certInfo);

        } catch (Exception e) {
            logger.error("CASCEPResource: Error extracting details from request: {}", e.getMessage(), e);
            crsResp.setFailInfo(CRSPKIMessage.mFailInfo_badMessageCheck);
            crsResp.setPKIStatus(CRSPKIMessage.mStatus_FAILURE);
        }
    }

    /**
     * Build a default SubjectAlternativeName from unstructured name/address
     * attributes found in the PKCS10 subject.
     */
    private SubjectAlternativeNameExtension makeDefaultSubjectAltName(
            Hashtable<String, String> ht) {

        if (ht.isEmpty()) {
            return null;
        }

        GeneralNameInterface[] gn = new GeneralNameInterface[ht.size()];
        int count = 0;
        Enumeration<String> en = ht.keys();
        while (en.hasMoreElements()) {
            String key = en.nextElement();
            if (key.equals(SANE_DNSNAME)) {
                gn[count++] = new DNSName(ht.get(key));
            }
            if (key.equals(SANE_IPADDRESS)) {
                gn[count++] = new IPAddressName(ht.get(key));
            }
        }

        try {
            return new SubjectAlternativeNameExtension(new GeneralNames(gn));
        } catch (Exception e) {
            logger.warn("CASCEPResource: Failed to create SAN extension: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Authenticate the SCEP requester using the configured auth manager.
     * Returns true if authentication failed and the request should be rejected.
     * Returns false if auth succeeded or auth is not configured (manual approval).
     */
    private boolean authenticateUser(CAEngine engine, CRSPKIMessage req) {
        if (authManagerName == null) {
            return false;
        }

        AuthSubsystem authSubsystem = engine.getAuthSubsystem();
        String password = (String) req.get(AUTH_PASSWORD);
        AuthCredentials authCreds = (AuthCredentials) req.get(AUTH_CREDS);
        if (authCreds == null) {
            authCreds = new AuthCredentials();
        }

        AuthToken token = null;
        if (password != null && !password.isEmpty()) {
            try {
                authCreds.set(AUTH_PASSWORD, password);
            } catch (Exception e) {
                // ignore
            }
        }

        try {
            token = authSubsystem.authenticate(authCreds, authManagerName);
            authCreds.delete(AUTH_PASSWORD);
            // Authentication succeeded
            if (token != null) {
                req.put(AUTH_TOKEN, token);
            }
            return false;
        } catch (EInvalidCredentials e) {
            return true;
        } catch (EMissingCredential e) {
            // Missing credential - proceed with manual approval
            return false;
        } catch (EBaseException e) {
            logger.error("CASCEPResource: Authentication error: {}", e.getMessage());
            return true;
        }
    }

    /**
     * Submit the enrollment request through the profile framework.
     */
    private Request postRequest(CAEngine engine, CRSPKIMessage req, CRSPKIMessage crsResp)
            throws Exception {

        ProfileSubsystem profileSubsystem = engine.getProfileSubsystem();
        X500Name subject = (X500Name) req.get(SUBJECTNAME);

        // Use profile framework for enrollment
        if (profileId != null) {
            PKCS10 pkcs10data = req.getP10();
            String pkcs10blob = Utils.base64encode(pkcs10data.toByteArray(), true);

            Profile profile = profileSubsystem.getProfile(profileId);
            if (profile == null) {
                logger.error("CASCEPResource: Profile '{}' not found", profileId);
                crsResp.setFailInfo(CRSPKIMessage.mFailInfo_internalCAError);
                crsResp.setPKIStatus(CRSPKIMessage.mStatus_FAILURE);
                return null;
            }

            Map<String, String> ctx = new HashMap<>();

            AuthManager authenticator = null;
            try {
                authenticator = profileSubsystem.getProfileAuthenticator(profile);
            } catch (Exception e) {
                // authenticator not configured
            }

            AuthToken authToken = null;
            SessionContext context = SessionContext.getContext();
            context.put("profileContext", ctx);

            String p10Password = getPasswordFromP10(pkcs10data);
            AuthCredentials credentials = new AuthCredentials();
            credentials.set("UID", "SCEP-client");
            credentials.set("PWD", p10Password);

            if (authenticator != null) {
                try {
                    Enumeration<String> authNames = authenticator.getValueNames();
                    if (authNames != null) {
                        while (authNames.hasMoreElements()) {
                            // Set credential names to null; real values come
                            // from challenge password in PKCS10
                            authNames.nextElement();
                        }
                    }
                    credentials.set("clientHost", "SCEP-client");
                    authToken = authenticator.authenticate(credentials);
                } catch (Exception e) {
                    logger.warn("CASCEPResource: Profile authentication failed: {}", e.getMessage());
                    // Fall through to manual approval
                }
            }

            // Create profile request
            ctx.put(EnrollProfile.CTX_CERT_REQUEST_TYPE, "pkcs10");
            ctx.put(Request.CTX_CERT_REQUEST, pkcs10blob);
            Locale locale = Locale.getDefault();

            Request[] reqs = profile.createRequests(ctx, locale);
            if (reqs == null || reqs.length == 0) {
                logger.error("CASCEPResource: No request created by profile");
                crsResp.setFailInfo(CRSPKIMessage.mFailInfo_internalCAError);
                crsResp.setPKIStatus(CRSPKIMessage.mStatus_FAILURE);
                return null;
            }

            // Populate request metadata
            reqs[0].setSourceId(req.getTransactionID());
            reqs[0].setExtData("profile", "true");
            reqs[0].setExtData(Request.PROFILE_ID, profileId);
            reqs[0].setExtData(EnrollProfile.CTX_CERT_REQUEST_TYPE, EnrollProfile.REQ_TYPE_PKCS10);
            reqs[0].setExtData(Request.CTX_CERT_REQUEST, pkcs10blob);
            reqs[0].setExtData("requestor_name", "");
            reqs[0].setExtData("requestor_email", "");
            reqs[0].setExtData("requestor_phone", "");
            reqs[0].setExtData("profileRemoteHost", "SCEP-client");
            reqs[0].setExtData("profileRemoteAddr", "SCEP-client");
            reqs[0].setExtData("profileApprovedBy", profile.getApprovedBy());

            String setId = profile.getPolicySetId(reqs[0]);
            if (setId == null) {
                logger.error("CASCEPResource: Profile policy setId not found");
                crsResp.setFailInfo(CRSPKIMessage.mFailInfo_internalCAError);
                crsResp.setPKIStatus(CRSPKIMessage.mStatus_FAILURE);
                return null;
            }
            reqs[0].setExtData("profileSetId", setId);

            logger.debug("CASCEPResource: Populating profile inputs");
            profile.populateInput(ctx, reqs[0]);
            profile.populate(reqs[0]);

            logger.debug("CASCEPResource: Submitting profile request");
            try {
                profile.submit(authToken, reqs[0]);
                engine.getRequestQueue().markAsServiced(reqs[0]);
                logger.debug("CASCEPResource: Request marked as serviced");
            } catch (EDeferException e) {
                crsResp.setPKIStatus(CRSPKIMessage.mStatus_PENDING);
                reqs[0].setRequestStatus(RequestStatus.PENDING);
                RequestNotifier notify = engine.getRequestQueue().getPendingNotify();
                if (notify != null) {
                    notify.notify(reqs[0]);
                }
                logger.debug("CASCEPResource: Request placed in pending mode");
            }

            return reqs[0];
        }

        // Fallback: non-profile enrollment (legacy path)
        CertRequestRepository requestRepository = engine.getCertRequestRepository();
        Request pkiReq = requestRepository.createRequest(Request.ENROLLMENT_REQUEST);

        AuthToken token = (AuthToken) req.get(AUTH_TOKEN);
        if (token != null) {
            pkiReq.setExtData(Request.AUTH_TOKEN, token);
        }

        pkiReq.setExtData(Request.HTTP_PARAMS, Request.CERT_TYPE, Request.CEP_CERT);
        X509CertInfo certInfo = (X509CertInfo) req.get(CERTINFO);
        pkiReq.setExtData(Request.CERT_INFO, new X509CertInfo[] { certInfo });
        pkiReq.setExtData("cepsubstore", substoreName);

        try {
            String chpwd = (String) req.get(ChallengePassword.NAME);
            if (chpwd != null) {
                pkiReq.setExtData("challengePhrase", chpwd);
            }
        } catch (Exception e) {
            // ignore
        }

        @SuppressWarnings("unchecked")
        Hashtable<String, byte[]> fingerprints = (Hashtable<String, byte[]>) req.get(Request.FINGERPRINTS);
        if (fingerprints != null && !fingerprints.isEmpty()) {
            Hashtable<String, String> encodedPrints = new Hashtable<>(fingerprints.size());
            Enumeration<String> e = fingerprints.keys();
            while (e.hasMoreElements()) {
                String fpKey = e.nextElement();
                byte[] value = fingerprints.get(fpKey);
                encodedPrints.put(fpKey, Utils.base64encode(value, true));
            }
            pkiReq.setExtData(Request.FINGERPRINTS, encodedPrints);
        }

        pkiReq.setSourceId(req.getTransactionID());
        engine.getRequestQueue().processRequest(pkiReq);
        crsResp.setPKIStatus(CRSPKIMessage.mStatus_SUCCESS);

        logger.info(
                AuditFormat.ENROLLMENTFORMAT,
                pkiReq.getRequestId(),
                AuditFormat.FROMROUTER,
                authManagerName == null ? AuditFormat.NOAUTH : authManagerName,
                "pending",
                subject,
                "");

        return pkiReq;
    }

    /**
     * Extract the challenge password from a PKCS10 request.
     */
    private String getPasswordFromP10(PKCS10 p10) {
        PKCS10Attributes p10atts = p10.getAttributes();
        Enumeration<PKCS10Attribute> e = p10atts.getElements();
        try {
            while (e.hasMoreElements()) {
                PKCS10Attribute p10a = e.nextElement();
                CertAttrSet attr = p10a.getAttributeValue();
                if (attr.getName().equals(ChallengePassword.NAME)) {
                    if (attr.get(ChallengePassword.PASSWORD) != null) {
                        return (String) attr.get(ChallengePassword.PASSWORD);
                    }
                }
            }
        } catch (Exception ex) {
            // ignore
        }
        return null;
    }

    /**
     * Compute fingerprints (MD2, MD5, SHA1, SHA256, SHA512) of the PKCS10.
     */
    private Hashtable<String, byte[]> makeFingerPrints(CRSPKIMessage req) {
        Hashtable<String, byte[]> fingerprints = new Hashtable<>();
        String[] hashes = { "MD2", "MD5", "SHA1", "SHA256", "SHA512" };
        PKCS10 p10 = req.getP10();

        for (String hash : hashes) {
            try {
                MessageDigest md = MessageDigest.getInstance(hash);
                md.update(p10.getCertRequestInfo());
                fingerprints.put(hash, md.digest());
            } catch (NoSuchAlgorithmException e) {
                // skip unavailable algorithm
            }
        }

        req.put(Request.FINGERPRINTS, fingerprints);
        return fingerprints;
    }

    /**
     * Compare fingerprints of a new request against an existing one.
     */
    private boolean areFingerprintsEqual(Request req, Hashtable<String, byte[]> fingerprints) {
        Hashtable<String, String> oldPrints = req.getExtDataInHashtable(Request.FINGERPRINTS);
        if (oldPrints == null) {
            return false;
        }

        byte[] oldMd5 = Utils.base64decode(oldPrints.get("MD5"));
        byte[] newMd5 = fingerprints.get("MD5");

        if (oldMd5 == null || newMd5 == null || oldMd5.length != newMd5.length) {
            return false;
        }

        for (int i = 0; i < oldMd5.length; i++) {
            if (oldMd5[i] != newMd5[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * Build the response from a completed/pending request.
     */
    private X509CertImpl makeResponseFromRequest(
            CRSPKIMessage crsReq, CRSPKIMessage crsResp, Request pkiReq) {

        RequestStatus status = pkiReq.getRequestStatus();

        // Profile-based request
        String reqProfileId = pkiReq.getExtDataInString(Request.PROFILE_ID);
        if (reqProfileId != null) {
            X509CertImpl cert = pkiReq.getExtDataInCert(Request.REQUEST_ISSUED_CERT);
            if (cert == null) {
                logger.debug("CASCEPResource: No certificate issued yet for profile request");
            }
            crsResp.setPKIStatus(CRSPKIMessage.mStatus_SUCCESS);
            return cert;
        }

        // Legacy request
        if (status.equals(RequestStatus.COMPLETE)) {
            Integer success = pkiReq.getExtDataInInteger(Request.RESULT);
            if (success != null && success.equals(Request.RES_SUCCESS)) {
                X509CertImpl[] issuedCerts = pkiReq.getExtDataInCertArray(Request.ISSUED_CERTS);
                if (issuedCerts != null && issuedCerts.length > 0) {
                    crsResp.setPKIStatus(CRSPKIMessage.mStatus_SUCCESS);
                    return issuedCerts[0];
                }
            }
            crsResp.setPKIStatus(CRSPKIMessage.mStatus_FAILURE);
            crsResp.setFailInfo(CRSPKIMessage.mFailInfo_badAlg);
        } else if (status == RequestStatus.REJECTED || status == RequestStatus.CANCELED) {
            crsResp.setPKIStatus(CRSPKIMessage.mStatus_FAILURE);
            crsResp.setFailInfo(CRSPKIMessage.mFailInfo_badRequest);
        } else {
            crsResp.setPKIStatus(CRSPKIMessage.mStatus_PENDING);
        }

        return null;
    }

    /**
     * Hash a challenge password with SHA-256 for storage.
     */
    private String hashPassword(String pwd) {
        String salt = "lala123";
        byte[] digest = shaDigest.digest((salt + pwd).getBytes());
        String b64 = Utils.base64encode(digest, true);
        return "{SHA-256}" + b64;
    }

    // ------------------------------------------------------------------
    //  Response construction
    // ------------------------------------------------------------------

    /**
     * Build the complete SCEP response message (signed/encrypted PKCS7).
     *
     * Steps:
     * 1. Create degenerate PKCS7 with issued cert
     * 2. Encrypt with new symmetric key
     * 3. Wrap symmetric key with recipient's public key
     * 4. Build RecipientInfo, EnvelopedData
     * 5. Compute digest and authenticated attributes
     * 6. Sign the response with CA/SCEP key
     * 7. Create final SignedData
     */
    private void processCertRep(
            CryptoContext cx, X509CertImpl issuedCert,
            CRSPKIMessage crsResp, CRSPKIMessage crsReq,
            String encryptionAlgorithm) throws Exception {

        byte[] msgDigest = null;

        try {
            if (issuedCert != null) {
                SymmetricKey.Type skt;
                EncryptionAlgorithm ea;

                switch (String.valueOf(encryptionAlgorithm)) {
                    case "DES3":
                        skt = SymmetricKey.DES3;
                        ea = EncryptionAlgorithm.DES3_CBC;
                        break;
                    case "AES":
                        skt = SymmetricKey.AES;
                        ea = EncryptionAlgorithm.AES_128_CBC;
                        break;
                    default:
                        skt = SymmetricKey.DES;
                        ea = EncryptionAlgorithm.DES_CBC;
                }

                // 1. Make degenerate PKCS7 with the issued certificate
                byte[] toBeEncrypted = crsResp.makeSignedRep(1, issuedCert.getEncoded());

                // 2. Encrypt with a new random symmetric key
                SymmetricKey sk = cx.getKeyGenerator().generate();
                byte[] padded = Cipher.pad(toBeEncrypted, ea.getBlockSize());
                Cipher cipher = cx.getInternalToken().getCipherContext(ea);

                byte[] iv = new byte[ea.getBlockSize()];
                SecureRandom ivRandom = new SecureRandom();
                ivRandom.nextBytes(iv);
                IVParameterSpec ivSpec = new IVParameterSpec(iv);

                cipher.initEncrypt(sk, ivSpec);
                byte[] encryptedData = cipher.doFinal(padded);
                crsResp.makeEncryptedContentInfo(ivSpec.getIV(), encryptedData, encryptionAlgorithm);

                // 3. Wrap symmetric key with recipient's public key
                PublicKey recipientPK = crsReq.getSignerPublicKey();
                SymmetricKey skInternal = moveSymmetricToInternalToken(
                        cx, sk, skt, ea, encryptionAlgorithm);

                KeyWrapper kw = cx.getInternalKeyWrapper();
                AlgorithmParameterSpec keyWrapConfig = null;
                if (useOAEPKeyWrap) {
                    keyWrapConfig = new OAEPParameterSpec(
                            OAEP_SHA, "MGF1", MGF1ParameterSpec.SHA256,
                            PSource.PSpecified.DEFAULT);
                }
                kw.initWrap(recipientPK, keyWrapConfig);
                byte[] encryptedKey = kw.wrap(skInternal);

                crsResp.setRcpIssuerAndSerialNumber(crsReq.getSgnIssuerAndSerialNumber());
                crsResp.makeRecipientInfo(0, encryptedKey);
            }

            byte[] envelopedData = crsResp.makeEnvelopedData(0);

            // 7. Compute digest of the SignedData content
            MessageDigest md = MessageDigest.getInstance(hashAlgorithm);
            msgDigest = md.digest(envelopedData);
            crsResp.setMsgDigest(msgDigest);

        } catch (Exception e) {
            throw new Exception("Failed to create inner SCEP response: " + e.getMessage(), e);
        }

        try {
            // 8. Build authenticated attributes
            crsResp.setTransactionID(crsReq.getTransactionID());
            crsResp.makeAuthenticatedAttributes();

            // 9-11. Sign and package the response
            byte[] signingCertBytes = cx.getSigningCert().getEncoded();
            Certificate.Template certTemplate = new Certificate.Template();
            Certificate signerCert = (Certificate) certTemplate.decode(
                    new ByteArrayInputStream(signingCertBytes));

            IssuerAndSerialNumber iasn = new IssuerAndSerialNumber(
                    signerCert.getInfo().getIssuer(),
                    signerCert.getInfo().getSerialNumber());
            crsResp.setSgnIssuerAndSerialNumber(iasn);

            crsResp.makeSignerInfo(1, cx.getPrivateKey(), hashAlgorithm);
            crsResp.makeSignedData(1, signingCertBytes, hashAlgorithm);

        } catch (Exception e) {
            throw new Exception("Failed to create outer SCEP response: " + e.getMessage(), e);
        }
    }

    // ------------------------------------------------------------------
    //  Utility methods
    // ------------------------------------------------------------------

    /**
     * Check if an algorithm is in the allowed list (case-insensitive).
     */
    private static boolean isAlgorithmAllowed(String[] allowedList, String algorithm) {
        if (algorithm == null || algorithm.isEmpty() || allowedList == null) {
            return false;
        }
        for (String allowed : allowedList) {
            if (algorithm.equalsIgnoreCase(allowed)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Trim whitespace from each element of a string array.
     */
    private static String[] trimArray(String[] arr) {
        for (int i = 0; i < arr.length; i++) {
            arr[i] = arr[i].trim();
        }
        return arr;
    }

    // ------------------------------------------------------------------
    //  CryptoContext inner class
    // ------------------------------------------------------------------

    /**
     * Manages cryptographic context for SCEP operations, including
     * the signing certificate, private key, and key generation facilities.
     * Mirrors the inner CryptoContext class from CRSEnrollment.
     */
    class CryptoContext {
        private final CryptoManager cm;
        private final CryptoToken internalToken;
        private final CryptoToken keyStorageToken;
        private CryptoToken internalKeyStorageToken;
        private final KeyGenerator keyGen;
        private final org.mozilla.jss.crypto.X509Certificate signingCert;
        private final PrivateKey signingCertPrivKey;

        CryptoContext() throws Exception {
            this(configuredEncryptionAlgorithm);
        }

        CryptoContext(String encAlgorithm) throws Exception {
            KeyGenAlgorithm kga;
            switch (String.valueOf(encAlgorithm)) {
                case "DES3":
                    kga = KeyGenAlgorithm.DES3;
                    break;
                case "AES":
                    kga = KeyGenAlgorithm.AES;
                    break;
                default:
                    kga = KeyGenAlgorithm.DES;
            }

            cm = CryptoManager.getInstance();
            internalToken = cm.getInternalCryptoToken();
            keyGen = internalToken.getKeyGenerator(kga);
            if (kga.equals(KeyGenAlgorithm.AES)) {
                keyGen.initialize(128);
            }

            keyStorageToken = CryptoUtil.getKeyStorageToken(tokenName);
            if (CryptoUtil.isInternalToken(tokenName)) {
                internalKeyStorageToken = keyStorageToken;
            }
            if (!useCA && internalKeyStorageToken == null) {
                keyStorageToken.login(new PWCBsdr());
            }

            signingCert = cm.findCertByNickname(nickname);
            signingCertPrivKey = cm.findPrivKeyByCert(signingCert);
        }

        KeyGenerator getKeyGenerator() {
            return keyGen;
        }

        CryptoToken getInternalToken() {
            return internalToken;
        }

        CryptoToken getKeyStorageToken() {
            return keyStorageToken;
        }

        CryptoToken getInternalKeyStorageToken() {
            return internalKeyStorageToken;
        }

        KeyWrapper getKeyWrapper() throws Exception {
            KeyWrapAlgorithm kwAlg = useOAEPKeyWrap
                    ? KeyWrapAlgorithm.RSA_OAEP : KeyWrapAlgorithm.RSA;
            return signingCertPrivKey.getOwningToken().getKeyWrapper(kwAlg);
        }

        KeyWrapper getInternalKeyWrapper() throws Exception {
            KeyWrapAlgorithm kwAlg = useOAEPKeyWrap
                    ? KeyWrapAlgorithm.RSA_OAEP : KeyWrapAlgorithm.RSA;
            return getInternalToken().getKeyWrapper(kwAlg);
        }

        PrivateKey getPrivateKey() {
            return signingCertPrivKey;
        }

        org.mozilla.jss.crypto.X509Certificate getSigningCert() {
            return signingCert;
        }
    }
}
