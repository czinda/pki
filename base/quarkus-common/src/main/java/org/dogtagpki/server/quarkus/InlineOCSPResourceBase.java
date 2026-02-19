//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.quarkus;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Response;

import org.mozilla.jss.netscape.security.util.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.logging.event.OCSPGenerationEvent;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmsutil.ocsp.OCSPRequest;
import com.netscape.cmsutil.ocsp.OCSPResponse;
import com.netscape.cmsutil.ocsp.TBSRequest;

/**
 * Base JAX-RS resource replacing the legacy OCSPServlet CMSServlet.
 * Processes OCSP requests per RFC 2560.
 * Subclasses provide the engine and validate method.
 */
public abstract class InlineOCSPResourceBase {

    private static final Logger logger = LoggerFactory.getLogger(InlineOCSPResourceBase.class);
    private static final int DEFAULT_MAX_REQUEST_SIZE = 5000;

    protected abstract CMSEngine getEngine();

    protected abstract OCSPResponse validate(OCSPRequest ocspRequest) throws Exception;

    @POST
    @Consumes("application/ocsp-request")
    @Produces("application/ocsp-response")
    public Response processOCSPPost(byte[] requestData) {

        logger.info("InlineOCSPResourceBase: Processing POST OCSP request");

        CMSEngine engine = getEngine();
        Auditor auditor = engine.getAuditor();

        if (requestData == null || requestData.length == 0) {
            logger.error("InlineOCSPResourceBase: Empty OCSP request");
            auditor.log(OCSPGenerationEvent.createFailureEvent(null, "Empty OCSP request"));
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        if (requestData.length > DEFAULT_MAX_REQUEST_SIZE) {
            logger.error("InlineOCSPResourceBase: OCSP request too large: {}", requestData.length);
            auditor.log(OCSPGenerationEvent.createFailureEvent(null, "OCSP request too large"));
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        return processOCSPRequest(new ByteArrayInputStream(requestData), auditor);
    }

    @GET
    @jakarta.ws.rs.Path("{encodedRequest:.+}")
    @Produces("application/ocsp-response")
    public Response processOCSPGet(@PathParam("encodedRequest") String encodedRequest) {

        logger.info("InlineOCSPResourceBase: Processing GET OCSP request");

        CMSEngine engine = getEngine();
        Auditor auditor = engine.getAuditor();

        if (encodedRequest == null || encodedRequest.isEmpty()) {
            logger.error("InlineOCSPResourceBase: Missing OCSP request in GET");
            auditor.log(OCSPGenerationEvent.createFailureEvent(null, "Missing OCSP request"));
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        try {
            String decoded = URLDecoder.decode(encodedRequest, StandardCharsets.UTF_8);
            byte[] requestBytes = Utils.base64decode(decoded);
            return processOCSPRequest(new ByteArrayInputStream(requestBytes), auditor);
        } catch (Exception e) {
            logger.error("InlineOCSPResourceBase: Failed to decode GET OCSP request: {}", e.getMessage(), e);
            auditor.log(OCSPGenerationEvent.createFailureEvent(null, e.getMessage()));
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
    }

    private Response processOCSPRequest(InputStream is, Auditor auditor) {

        try {
            OCSPRequest.Template reqTemplate = new OCSPRequest.Template();
            OCSPRequest ocspReq = (OCSPRequest) reqTemplate.decode(is);

            if (ocspReq == null) {
                logger.error("InlineOCSPResourceBase: Empty or malformed OCSP request");
                auditor.log(OCSPGenerationEvent.createFailureEvent(null, "Empty or malformed OCSP request"));
                return Response.status(Response.Status.BAD_REQUEST).build();
            }

            if (logger.isDebugEnabled()) {
                TBSRequest tbsReq = ocspReq.getTBSRequest();
                logger.debug("InlineOCSPResourceBase: Cert status requests:");
                for (int i = 0; i < tbsReq.getRequestCount(); i++) {
                    com.netscape.cmsutil.ocsp.Request req = tbsReq.getRequestAt(i);
                    CertId certID = new CertId(req.getCertID().getSerialNumber());
                    logger.debug("InlineOCSPResourceBase: - {}", certID.toHexString());
                }
            }

            OCSPResponse response = validate(ocspReq);

            if (response == null) {
                auditor.log(OCSPGenerationEvent.createFailureEvent(null, "Missing OCSP response"));
                return Response.serverError().build();
            }

            auditor.log(OCSPGenerationEvent.createSuccessEvent(null));

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            response.encode(bos);
            bos.close();

            return Response.ok(bos.toByteArray(), "application/ocsp-response").build();

        } catch (Exception e) {
            logger.error("InlineOCSPResourceBase: Error processing OCSP request: {}", e.getMessage(), e);
            auditor.log(OCSPGenerationEvent.createFailureEvent(null, e.getMessage()));
            return Response.serverError().build();
        }
    }
}
