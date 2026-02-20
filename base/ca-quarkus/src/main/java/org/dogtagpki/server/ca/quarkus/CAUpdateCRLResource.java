//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.util.Collections;
import java.util.Enumeration;

import jakarta.inject.Inject;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.ca.CAEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.ca.CRLIssuingPoint;
import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.ca.EErrorPublishCRL;
import com.netscape.certsrv.logging.event.ScheduleCRLGenerationEvent;
import com.netscape.cmscore.ldap.CAPublisherProcessor;
import com.netscape.cmscore.ldap.LdapRule;
import com.netscape.cmscore.logging.Auditor;

/**
 * JAX-RS resource replacing the legacy UpdateCRL CMSServlet.
 * Forces CRL generation/update for a specified issuing point.
 * Legacy URL: /agent/ca/updateCRL
 */
@Path("agent/ca/updateCRL")
public class CAUpdateCRLResource {

    private static final Logger logger = LoggerFactory.getLogger(CAUpdateCRLResource.class);

    @Inject
    CAEngineQuarkus engineQuarkus;

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response updateCRL(
            @FormParam("signatureAlgorithm") String signatureAlgorithm,
            @FormParam("waitForUpdate") String waitForUpdate,
            @FormParam("clearCRLCache") String clearCache,
            @FormParam("crlIssuingPoint") String crlIssuingPointId) {

        logger.info("CAUpdateCRLResource: Updating CRL");

        CAEngine engine = engineQuarkus.getEngine();
        Auditor auditor = engine.getAuditor();

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode result = mapper.createObjectNode();

        // Validate CRL issuing point
        if (crlIssuingPointId != null) {
            boolean found = false;
            for (CRLIssuingPoint ip : engine.getCRLIssuingPoints()) {
                if (crlIssuingPointId.equals(ip.getId())) {
                    found = true;
                    break;
                }
            }
            if (!found) crlIssuingPointId = null;
        }

        if (crlIssuingPointId == null) {
            crlIssuingPointId = CertificateAuthority.PROP_MASTER_CRL;
        }

        logger.info("CAUpdateCRLResource: Issuing point: {}", crlIssuingPointId);

        CRLIssuingPoint crlIssuingPoint = engine.getCRLIssuingPoint(crlIssuingPointId);
        result.put("crlIssuingPoint", crlIssuingPointId);

        if (crlIssuingPoint == null) {
            result.put("Status", "1");
            result.put("Error", "CRL issuing point not found: " + crlIssuingPointId);
            return Response.status(Response.Status.NOT_FOUND)
                    .entity(result.toString())
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        // Clear cache if requested
        if ("true".equals(clearCache) &&
                crlIssuingPoint.isCRLGenerationEnabled() &&
                crlIssuingPoint.isCRLUpdateInProgress() == CRLIssuingPoint.CRL_UPDATE_DONE &&
                crlIssuingPoint.isCRLIssuingPointInitialized()) {
            logger.debug("CAUpdateCRLResource: Clearing CRL cache");
            crlIssuingPoint.clearCRLCache();
        }

        // If not waiting for update, schedule and return
        if (!("true".equals(waitForUpdate) &&
                crlIssuingPoint.isCRLGenerationEnabled() &&
                crlIssuingPoint.isCRLUpdateInProgress() == CRLIssuingPoint.CRL_UPDATE_DONE &&
                crlIssuingPoint.isCRLIssuingPointInitialized())) {

            if (!crlIssuingPoint.isCRLIssuingPointInitialized()) {
                result.put("crlUpdate", "notInitialized");
            } else if (crlIssuingPoint.isCRLUpdateInProgress() != CRLIssuingPoint.CRL_UPDATE_DONE ||
                       crlIssuingPoint.isManualUpdateSet()) {
                result.put("crlUpdate", "inProgress");
            } else if (!crlIssuingPoint.isCRLGenerationEnabled()) {
                result.put("crlUpdate", "Disabled");
            } else {
                try {
                    crlIssuingPoint.setManualUpdate(signatureAlgorithm);
                    result.put("crlUpdate", "Scheduled");
                    auditor.log(new ScheduleCRLGenerationEvent(null));
                } catch (Exception e) {
                    auditor.log(new ScheduleCRLGenerationEvent(null, e));
                    result.put("crlUpdate", "Failure");
                    result.put("Error", e.getMessage());
                }
            }

            result.put("Status", "0");
            return Response.ok(result.toString(), MediaType.APPLICATION_JSON).build();
        }

        // Synchronous CRL update
        logger.info("CAUpdateCRLResource: Performing synchronous CRL update for {}", crlIssuingPointId);
        CAPublisherProcessor lpm = engine.getPublisherProcessor();

        try {
            long now1 = System.currentTimeMillis();

            if (signatureAlgorithm != null) {
                crlIssuingPoint.updateCRLNow(signatureAlgorithm);
            } else {
                crlIssuingPoint.updateCRLNow();
            }

            long now2 = System.currentTimeMillis();
            result.put("time", String.valueOf(now2 - now1));
            result.put("Status", "0");
            result.put("crlUpdate", "Success");

            if (lpm != null && lpm.isCRLPublishingEnabled()) {
                Enumeration<LdapRule> rules = lpm.getRules(CAPublisherProcessor.PROP_LOCAL_CRL);
                if (rules != null && rules.hasMoreElements()) {
                    result.put("crlPublished", "Success");
                }
            }

        } catch (EErrorPublishCRL e) {
            result.put("Status", "0");
            result.put("crlUpdate", "Success");
            result.put("crlPublished", "Failure");
            result.put("publishError", e.getMessage());

        } catch (EBaseException e) {
            logger.error("CAUpdateCRLResource: Error updating CRL: {}", e.getMessage(), e);
            result.put("Status", "1");
            result.put("crlUpdate", "Failure");
            result.put("Error", e.getMessage());
            return Response.serverError()
                    .entity(result.toString())
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        return Response.ok(result.toString(), MediaType.APPLICATION_JSON).build();
    }
}
