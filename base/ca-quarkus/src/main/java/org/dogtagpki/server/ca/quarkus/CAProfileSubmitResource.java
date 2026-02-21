//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.authentication.AuthManager;
import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.authentication.AuthCredentials;
import com.netscape.certsrv.authentication.ISSLClientCertProvider;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.cert.CertEnrollmentRequest;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.ProfileAttribute;
import com.netscape.certsrv.profile.ProfileInput;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.profile.common.Profile;
import com.netscape.cms.profile.common.ProfileOutput;
import com.netscape.cmscore.authorization.AuthzSubsystem;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.profile.ProfileSubsystem;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestNotifier;
import com.netscape.cmsutil.ldap.LDAPUtil;

/**
 * JAX-RS resource that replaces the legacy ProfileSubmitServlet for Quarkus.
 *
 * This endpoint handles certificate enrollment requests from pkispawn and
 * other clients that use the legacy form-encoded /ee/ca/profileSubmit API.
 * It processes enrollment using the Profile subsystem directly, bypassing
 * the servlet-dependent EnrollmentProcessor/CertProcessor hierarchy.
 *
 * The endpoint supports install-token authentication (TokenAuthentication)
 * used during subsystem installation via pkispawn.
 */
@Path("ee/ca/profileSubmit")
public class CAProfileSubmitResource {

    private static final Logger logger = LoggerFactory.getLogger(CAProfileSubmitResource.class);

    @Inject
    CAEngineQuarkus engineQuarkus;

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_XML)
    public Response profileSubmit(
            @FormParam("profileId") String profileId,
            @FormParam("cert_request_type") String certRequestType,
            @FormParam("cert_request") String certRequest,
            @FormParam("renewal") String renewal,
            @FormParam("xmlOutput") String xmlOutput,
            @FormParam("sessionID") String sessionID,
            @FormParam("subject") String subject,
            @FormParam("uid") String uid,
            @FormParam("requestor_name") String requestorName,
            @FormParam("req_san_entries") String sanEntries,
            @FormParam("req_san_pattern_0") String sanPattern0,
            @FormParam("req_san_pattern_1") String sanPattern1,
            @FormParam("req_san_pattern_2") String sanPattern2,
            @FormParam("req_san_pattern_3") String sanPattern3) {

        logger.info("CAProfileSubmitResource: Processing enrollment request for profile: {}", profileId);

        try {
            return processEnrollment(
                    profileId, certRequestType, certRequest, sessionID,
                    subject, uid, requestorName,
                    sanEntries, sanPattern0, sanPattern1, sanPattern2, sanPattern3);
        } catch (Exception e) {
            logger.error("CAProfileSubmitResource: Enrollment failed: {}", e.getMessage(), e);
            return buildErrorResponse("1", e.getMessage());
        }
    }

    private Response processEnrollment(
            String profileId,
            String certRequestType,
            String certRequest,
            String sessionID,
            String subject,
            String uid,
            String requestorName,
            String sanEntries,
            String sanPattern0,
            String sanPattern1,
            String sanPattern2,
            String sanPattern3) throws Exception {

        CAEngine engine = engineQuarkus.getEngine();
        Locale locale = Locale.getDefault();

        // 1. Get profile
        ProfileSubsystem ps = engine.getProfileSubsystem();
        Profile profile = ps.getProfile(profileId);
        if (profile == null) {
            logger.error("CAProfileSubmitResource: Profile not found: {}", profileId);
            return buildErrorResponse("1", "Profile not found: " + profileId);
        }
        if (!ps.isProfileEnable(profileId)) {
            logger.error("CAProfileSubmitResource: Profile not enabled: {}", profileId);
            return buildErrorResponse("1", "Profile not enabled: " + profileId);
        }

        // 2. Build context map with input data
        Map<String, String> ctx = new HashMap<>();

        // Build a CertEnrollmentRequest with the profile inputs populated from form params
        CertEnrollmentRequest data = new CertEnrollmentRequest();
        data.setProfileId(profileId);
        data.setRemoteHost("");
        data.setRemoteAddr("");

        // Map form parameters to profile input attributes
        Map<String, String> formParams = new HashMap<>();
        if (certRequestType != null) formParams.put("cert_request_type", certRequestType);
        if (certRequest != null) formParams.put("cert_request", certRequest);
        if (subject != null) formParams.put("subject", subject);
        if (uid != null) formParams.put("uid", uid);
        if (requestorName != null) formParams.put("requestor_name", requestorName);

        // Add SAN parameters
        if (sanEntries != null) formParams.put("req_san_entries", sanEntries);
        if (sanPattern0 != null) formParams.put("req_san_pattern_0", sanPattern0);
        if (sanPattern1 != null) formParams.put("req_san_pattern_1", sanPattern1);
        if (sanPattern2 != null) formParams.put("req_san_pattern_2", sanPattern2);
        if (sanPattern3 != null) formParams.put("req_san_pattern_3", sanPattern3);

        // Subject DN components (sn_ prefixed)
        if (subject != null) {
            formParams.put("sn_cn", subject);
        }

        // Populate CertEnrollmentRequest with profile inputs
        Enumeration<String> inputIds = profile.getProfileInputIds();
        while (inputIds.hasMoreElements()) {
            String inputId = inputIds.nextElement();
            com.netscape.cms.profile.common.ProfileInput profileInput = profile.getProfileInput(inputId);
            ProfileInput input = new ProfileInput();
            input.setName(profileInput.getName(locale));
            input.setClassId(profileInput.getClass().getSimpleName());

            Enumeration<String> inputNames = profileInput.getValueNames();
            while (inputNames.hasMoreElements()) {
                String inputName = inputNames.nextElement();
                String value = formParams.get(inputName);
                if (value != null) {
                    input.addAttribute(new ProfileAttribute(inputName, value, null));
                }
            }
            data.addInput(input);
        }

        // Set inputs into context (mirrors EnrollmentProcessor.setInputsIntoContext)
        setInputsIntoContext(data, profile, ctx);

        // 3. Setup authentication credentials
        AuthManager authenticator = ps.getProfileAuthenticator(profile);
        AuthToken authToken = null;

        if (authenticator != null) {
            logger.debug("CAProfileSubmitResource: Authenticator: {}", authenticator.getName());

            // Build credentials from form parameters
            AuthCredentials credentials = new AuthCredentials();
            if (sessionID != null) {
                credentials.set(AuthManager.CRED_SESSION_ID, sessionID);
            }
            credentials.set("clientHost", "");

            // Set credentials into context
            Enumeration<String> credNames = authenticator.getValueNames();
            if (credNames != null) {
                while (credNames.hasMoreElements()) {
                    String name = credNames.nextElement();
                    Object value = credentials.get(name);
                    if (value != null) {
                        ctx.put(name, value.toString());
                    }
                }
            }

            // Setup SessionContext
            SessionContext sessionContext = SessionContext.getContext();
            sessionContext.put("profileContext", ctx);
            // Provide a no-op SSL client cert provider (install token auth doesn't need client certs)
            sessionContext.put("sslClientCertProvider", (ISSLClientCertProvider) () -> null);

            // Authenticate
            authToken = authenticator.authenticate(credentials);
            logger.debug("CAProfileSubmitResource: Authentication successful");

            if (authToken != null) {
                sessionContext.put(SessionContext.AUTH_MANAGER_ID, authenticator.getName());
                String userid = authToken.getInString(AuthToken.USER_ID);
                if (userid != null) {
                    sessionContext.put(SessionContext.USER_ID, userid);
                }
            }
        }

        // 4. Authorize
        if (authToken != null) {
            String acl = profile.getAuthzAcl();
            if (acl != null && !acl.isEmpty()) {
                AuthzSubsystem authz = engine.getAuthzSubsystem();
                String resource = profileId + ".authz.acl";
                authz.authorize("BasicAclAuthz", authToken, acl);
            }
        }

        try {
            // 5. Create requests
            Request[] reqs = profile.createRequests(ctx, locale);
            logger.debug("CAProfileSubmitResource: Created {} request(s)", reqs.length);

            // 6. Populate requests
            populateRequests(data, profileId, profile, ctx, authenticator, authToken, reqs);

            // 7. Submit requests
            String errorCode = submitRequests(locale, profile, authToken, reqs, engine);

            if (errorCode != null) {
                String errorMsg = "";
                for (Request req : reqs) {
                    String error = req.getError(locale);
                    if (error != null) {
                        errorMsg += error + "\n";
                    }
                }
                return buildErrorResponse(errorCode, errorMsg.isEmpty() ? "Request processing failed" : errorMsg);
            }

            // 8. Build XML response
            return buildXmlResponse(profile, locale, reqs);

        } finally {
            SessionContext.releaseContext();
        }
    }

    /**
     * Set profile inputs into context map.
     * Mirrors EnrollmentProcessor.setInputsIntoContext().
     */
    private void setInputsIntoContext(CertEnrollmentRequest data, Profile profile, Map<String, String> ctx) {
        HashMap<String, String> dataInputs = new HashMap<>();
        for (ProfileInput input : data.getInputs()) {
            for (ProfileAttribute attr : input.getAttributes()) {
                dataInputs.put(attr.getName(), attr.getValue());
            }
        }

        Enumeration<String> inputIds = profile.getProfileInputIds();
        if (inputIds != null) {
            while (inputIds.hasMoreElements()) {
                String inputId = inputIds.nextElement();
                com.netscape.cms.profile.common.ProfileInput profileInput = profile.getProfileInput(inputId);
                Enumeration<String> inputNames = profileInput.getValueNames();
                while (inputNames.hasMoreElements()) {
                    String inputName = inputNames.nextElement();
                    if (dataInputs.containsKey(inputName)) {
                        if (inputName.matches("^sn_.*")) {
                            ctx.put(inputName, LDAPUtil.escapeRDNValue(dataInputs.get(inputName)));
                        } else {
                            ctx.put(inputName, dataInputs.get(inputName));
                        }
                    }
                }
            }
        }
    }

    /**
     * Populate request objects with enrollment data.
     * Mirrors CertProcessor.populateRequests() for non-renewal case.
     */
    private void populateRequests(
            CertEnrollmentRequest data,
            String profileId,
            Profile profile,
            Map<String, String> ctx,
            AuthManager authenticator,
            AuthToken authToken,
            Request[] reqs) throws Exception {

        for (Request req : reqs) {
            // Set input data into request
            setInputsIntoRequest(data, profile, req);

            // Set auth token data into request
            if (authToken != null) {
                setAuthTokenIntoRequest(req, authToken);

                // If RA agent, auto-assign the request
                String raGroupName = "Registration Manager Agents";
                if (raGroupName.equals(authToken.getInString(AuthToken.GROUP))) {
                    String uidVal = authToken.getInString(AuthToken.UID);
                    if (uidVal == null) uidVal = "";
                    req.setExtData("requestOwner", uidVal);
                }
            }

            // Set profile framework parameters
            req.setExtData("profile", "true");
            req.setExtData(Request.PROFILE_ID, profileId);
            req.setExtData("profileApprovedBy", profile.getApprovedBy());

            String setId = profile.getPolicySetId(req);
            if (setId == null) {
                throw new EBaseException("No profile policy set found");
            }
            req.setExtData("profileSetId", setId);
            req.setExtData("profileRemoteHost", data.getRemoteHost());
            req.setExtData("profileRemoteAddr", data.getRemoteAddr());

            // Let authenticator populate request
            if (authenticator != null) {
                authenticator.populate(authToken, req);
            }

            // Let profile populate
            profile.populateInput(ctx, req);
            profile.populate(req);
        }
    }

    /**
     * Set input data from CertEnrollmentRequest into Request.
     * Mirrors CertProcessor.setInputsIntoRequest().
     */
    private void setInputsIntoRequest(CertEnrollmentRequest data, Profile profile, Request req) {
        HashMap<String, String> dataInputs = new HashMap<>();
        for (ProfileInput input : data.getInputs()) {
            for (ProfileAttribute attr : input.getAttributes()) {
                dataInputs.put(attr.getName(), attr.getValue());
            }
        }

        Enumeration<String> inputIds = profile.getProfileInputIds();
        if (inputIds != null) {
            while (inputIds.hasMoreElements()) {
                String inputId = inputIds.nextElement();
                com.netscape.cms.profile.common.ProfileInput profileInput = profile.getProfileInput(inputId);
                Enumeration<String> inputNames = profileInput.getValueNames();
                if (inputNames != null) {
                    while (inputNames.hasMoreElements()) {
                        String inputName = inputNames.nextElement();
                        if (dataInputs.containsKey(inputName)) {
                            if (inputName.matches("^sn_.*")) {
                                req.setExtData(inputName, LDAPUtil.escapeRDNValue(dataInputs.get(inputName)));
                            } else {
                                req.setExtData(inputName, dataInputs.get(inputName));
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * Set auth token values into request.
     * Mirrors CertProcessor.setAuthTokenIntoRequest().
     */
    private void setAuthTokenIntoRequest(Request req, AuthToken authToken) {
        Enumeration<String> tokenNames = authToken.getElements();
        while (tokenNames.hasMoreElements()) {
            String tokenName = tokenNames.nextElement();
            String[] tokenVals = authToken.getInStringArray(tokenName);
            if (tokenVals != null) {
                for (int i = 0; i < tokenVals.length; i++) {
                    req.setExtData(Request.AUTH_TOKEN_PREFIX + "." + tokenName + "[" + i + "]", tokenVals[i]);
                }
            } else {
                String tokenVal = authToken.getInString(tokenName);
                if (tokenVal != null) {
                    req.setExtData(Request.AUTH_TOKEN_PREFIX + "." + tokenName, tokenVal);
                }
            }
        }
    }

    /**
     * Submit requests to the CA for processing.
     * Mirrors CertProcessor.submitRequests() with simplified audit logging.
     */
    private String submitRequests(
            Locale locale,
            Profile profile,
            AuthToken authToken,
            Request[] reqs,
            CAEngine engine) {

        String errorCode = null;

        for (Request req : reqs) {
            try {
                ConfigStore profileConf = profile.getConfigStore().getSubStore("auth", ConfigStore.class);
                boolean explicitApprovalRequired = profileConf.getBoolean("explicitApprovalRequired", false);

                logger.info("CAProfileSubmitResource: Submitting request {} to profile {}", req.getRequestId(), profile.getId());

                if (logger.isDebugEnabled()) {
                    Enumeration<String> reqKeys = req.getExtDataKeys();
                    while (reqKeys.hasMoreElements()) {
                        String reqKey = reqKeys.nextElement();
                        String reqVal = req.getExtDataInString(reqKey);
                        if (reqVal != null) {
                            logger.debug("CAProfileSubmitResource: - {}: {}", reqKey, reqVal);
                        }
                    }
                }

                profile.submit(authToken, req, explicitApprovalRequired);
                req.setRequestStatus(RequestStatus.COMPLETE);
                engine.getRequestQueue().markAsServiced(req);

                X509CertImpl cert = req.getExtDataInCert(Request.REQUEST_ISSUED_CERT);
                if (cert != null) {
                    logger.info("CAProfileSubmitResource: Certificate issued: serial={}", cert.getSerialNumber().toString(16));
                }

            } catch (com.netscape.certsrv.profile.EDeferException e) {
                logger.warn("CAProfileSubmitResource: Request deferred: {}", e.getMessage());
                req.setRequestStatus(RequestStatus.PENDING);
                RequestNotifier notify = engine.getRequestQueue().getPendingNotify();
                if (notify != null) {
                    notify.notify(req);
                }
                errorCode = "2";
                req.setExtData(Request.ERROR_CODE, errorCode);
                try {
                    engine.getRequestRepository().updateRequest(req);
                } catch (EBaseException ex) {
                    logger.warn("CAProfileSubmitResource: Failed to update deferred request: {}", ex.getMessage());
                }

            } catch (com.netscape.certsrv.profile.ERejectException e) {
                logger.warn("CAProfileSubmitResource: Request rejected: {}", e.getMessage());
                req.setRequestStatus(RequestStatus.REJECTED);
                errorCode = "3";
                req.setExtData(Request.ERROR, e.toString());
                req.setExtData(Request.ERROR_CODE, errorCode);
                try {
                    engine.getRequestRepository().updateRequest(req);
                } catch (EBaseException ex) {
                    logger.warn("CAProfileSubmitResource: Failed to update rejected request: {}", ex.getMessage());
                }

            } catch (Throwable e) {
                logger.error("CAProfileSubmitResource: Request failed: {}", e.getMessage(), e);
                errorCode = "1";
                req.setExtData(Request.ERROR, e.getMessage());
                req.setExtData(Request.ERROR_CODE, errorCode);
                try {
                    engine.getRequestRepository().updateRequest(req);
                } catch (EBaseException ex) {
                    logger.warn("CAProfileSubmitResource: Failed to update failed request: {}", ex.getMessage());
                }
            }
        }

        return errorCode;
    }

    /**
     * Build XML success response matching the format expected by CACertClient.
     * Uses string building to avoid dependency on XMLObject/Xerces.
     */
    private Response buildXmlResponse(Profile profile, Locale locale, Request[] reqs) {
        try {
            StringBuilder xml = new StringBuilder();
            xml.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
            xml.append("<XMLResponse>");
            xml.append("<Status>0</Status>");
            xml.append("<Requests>");

            for (Request req : reqs) {
                xml.append("<Request>");
                xml.append("<Id>").append(escapeXml(req.getRequestId().toString())).append("</Id>");

                // Add subject DN from cert info
                X509CertInfo certInfo = req.getExtDataInCertInfo(Request.REQUEST_CERTINFO);
                if (certInfo != null) {
                    try {
                        String subjectDN = certInfo.get(X509CertInfo.SUBJECT).toString();
                        xml.append("<SubjectDN>").append(escapeXml(subjectDN)).append("</SubjectDN>");
                    } catch (Exception e) {
                        logger.warn("CAProfileSubmitResource: Could not get subject DN: {}", e.getMessage());
                    }
                }

                // Add certificate output (b64, serial, pkcs7)
                Enumeration<String> outputIds = profile.getProfileOutputIds();
                if (outputIds != null) {
                    while (outputIds.hasMoreElements()) {
                        String outputId = outputIds.nextElement();
                        ProfileOutput profileOutput = profile.getProfileOutput(outputId);
                        Enumeration<String> outputNames = profileOutput.getValueNames();
                        if (outputNames != null) {
                            while (outputNames.hasMoreElements()) {
                                String outputName = outputNames.nextElement();
                                if (!outputName.equals("b64_cert") &&
                                        !outputName.equals("der") &&
                                        !outputName.equals("pkcs7")) {
                                    continue;
                                }
                                try {
                                    String outputValue = profileOutput.getValue(outputName, locale, req);
                                    if (outputName.equals("b64_cert") || outputName.equals("der")) {
                                        String normalized = Cert.normalizeCertStrAndReq(outputValue);
                                        outputValue = Cert.stripBrackets(normalized);
                                        byte[] bcode = Utils.base64decode(outputValue);
                                        X509CertImpl impl = new X509CertImpl(bcode);
                                        xml.append("<serialno>")
                                                .append(impl.getSerialNumber().toString(16))
                                                .append("</serialno>");
                                        xml.append("<b64>").append(outputValue).append("</b64>");
                                    } else if (outputName.equals("pkcs7")) {
                                        String normalized = Cert.normalizeCertStrAndReq(outputValue);
                                        xml.append("<pkcs7>").append(normalized).append("</pkcs7>");
                                    }
                                } catch (EProfileException e) {
                                    logger.warn("CAProfileSubmitResource: Output error: {}", e.getMessage());
                                }
                            }
                        }
                    }
                }

                xml.append("</Request>");
            }

            xml.append("</Requests>");
            xml.append("</XMLResponse>");

            return Response.ok(xml.toString(), MediaType.APPLICATION_XML).build();

        } catch (Exception e) {
            logger.error("CAProfileSubmitResource: Failed to build XML response: {}", e.getMessage(), e);
            return buildErrorResponse("1", "Failed to build response: " + e.getMessage());
        }
    }

    /**
     * Build XML error response matching the format expected by CACertClient.
     */
    private Response buildErrorResponse(String status, String error) {
        String safeError = escapeXml(error != null ? error : "Unknown error");
        return Response.ok(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><XMLResponse><Status>" +
                        status + "</Status><Error>" + safeError + "</Error></XMLResponse>",
                MediaType.APPLICATION_XML).build();
    }

    /**
     * Escape special XML characters in a string.
     */
    private static String escapeXml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&apos;");
    }
}
