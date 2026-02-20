//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.util.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.logging.event.OCSPGenerationEvent;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmsutil.ocsp.OCSPRequest;
import com.netscape.cmsutil.ocsp.OCSPResponse;
import com.netscape.cmsutil.ocsp.TBSRequest;

import io.vertx.ext.web.RoutingContext;

/**
 * JAX-RS resource replacing the legacy CAOCSPServlet.
 * Handles OCSP requests per RFC 6960 (formerly RFC 2560).
 *
 * Legacy URLs: /ocsp, /ocsp/*
 */
@Path("ocsp")
public class CAOCSPResource {

    private static final Logger logger = LoggerFactory.getLogger(CAOCSPResource.class);
    private static final String OCSP_RESPONSE_TYPE = "application/ocsp-response";
    private static final int MAX_REQUEST_SIZE = 5000;

    @Inject
    CAEngineQuarkus engineQuarkus;

    @Context
    RoutingContext routingContext;

    @POST
    @Consumes("application/ocsp-request")
    @Produces(OCSP_RESPONSE_TYPE)
    public Response handlePost(byte[] requestBytes) {
        logger.debug("CAOCSPResource: Processing POST OCSP request");

        if (requestBytes == null || requestBytes.length == 0) {
            logger.error("CAOCSPResource: Empty OCSP request");
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        if (requestBytes.length > MAX_REQUEST_SIZE) {
            logger.error("CAOCSPResource: OCSP request too large: {}", requestBytes.length);
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        return processOCSPRequest(new ByteArrayInputStream(requestBytes));
    }

    @GET
    @Path("{encoded:.+}")
    @Produces(OCSP_RESPONSE_TYPE)
    public Response handleGet(@jakarta.ws.rs.PathParam("encoded") String encoded) {
        logger.debug("CAOCSPResource: Processing GET OCSP request");

        if (encoded == null || encoded.isEmpty()) {
            logger.error("CAOCSPResource: Missing OCSP request data in GET");
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        try {
            String decoded = URLDecoder.decode(encoded, StandardCharsets.UTF_8);
            byte[] requestBytes = Utils.base64decode(decoded);
            return processOCSPRequest(new ByteArrayInputStream(requestBytes));

        } catch (Exception e) {
            logger.error("CAOCSPResource: Error decoding GET OCSP request", e);
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
    }

    private Response processOCSPRequest(InputStream is) {
        CAEngine engine = engineQuarkus.getEngine();
        Auditor auditor = engine.getAuditor();

        try {
            OCSPRequest.Template reqTemplate = new OCSPRequest.Template();
            OCSPRequest ocspReq = (OCSPRequest) reqTemplate.decode(is);

            if (ocspReq == null) {
                logger.error("CAOCSPResource: Failed to decode OCSP request");
                auditor.log(OCSPGenerationEvent.createFailureEvent(null, "Empty or malformed OCSP request"));
                return Response.status(Response.Status.BAD_REQUEST).build();
            }

            TBSRequest tbsReq = ocspReq.getTBSRequest();
            if (logger.isDebugEnabled()) {
                logger.debug("CAOCSPResource: Cert status requests:");
                for (int i = 0; i < tbsReq.getRequestCount(); i++) {
                    com.netscape.cmsutil.ocsp.Request req = tbsReq.getRequestAt(i);
                    CertId certID = new CertId(req.getCertID().getSerialNumber());
                    logger.debug("CAOCSPResource: - {}", certID.toHexString());
                }
            }

            CertificateAuthority ca = engine.getCA();
            OCSPResponse response = engine.validate(ca, ocspReq);

            if (response == null) {
                auditor.log(OCSPGenerationEvent.createFailureEvent(null, "Missing OCSP response"));
                return Response.serverError().build();
            }

            auditor.log(OCSPGenerationEvent.createSuccessEvent(null));

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            response.encode(bos);
            byte[] respBytes = bos.toByteArray();

            return Response.ok(respBytes, OCSP_RESPONSE_TYPE).build();

        } catch (Exception e) {
            logger.error("CAOCSPResource: Error processing OCSP request", e);
            auditor.log(OCSPGenerationEvent.createFailureEvent(null, e.getMessage()));
            return Response.serverError().build();
        }
    }
}
