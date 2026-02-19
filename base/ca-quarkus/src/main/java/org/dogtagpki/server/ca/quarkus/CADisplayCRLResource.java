//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.util.Collections;
import java.util.Enumeration;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CAEngineConfig;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.X509CRLImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.ca.CRLIssuingPoint;
import com.netscape.cmscore.dbs.CRLIssuingPointRecord;
import com.netscape.cmscore.dbs.CRLRepository;

/**
 * JAX-RS resource replacing the legacy DisplayCRL CMSServlet.
 * Displays CRL information for a specified issuing point.
 * Legacy URL: /agent/ca/displayCRL
 */
@Path("agent/ca/displayCRL")
public class CADisplayCRLResource {

    private static final Logger logger = LoggerFactory.getLogger(CADisplayCRLResource.class);

    @Inject
    CAEngineQuarkus engineQuarkus;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response displayCRL(
            @QueryParam("crlIssuingPoint") String crlIssuingPointId,
            @QueryParam("crlDisplayType") String crlDisplayType,
            @QueryParam("pageStart") String pageStart,
            @QueryParam("pageSize") String pageSize) {

        logger.info("CADisplayCRLResource: Displaying CRL");

        CAEngine engine = engineQuarkus.getEngine();
        CRLRepository crlRepository = engine.getCRLRepository();

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode result = mapper.createObjectNode();

        // Validate issuing point
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
            result.put("Status", "1");
            result.put("Error", "CRL issuing point not specified or not found");
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(result.toString())
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        if (crlDisplayType == null) crlDisplayType = "crlHeader";

        try {
            CRLIssuingPointRecord crlRecord = crlRepository.readCRLIssuingPointRecord(crlIssuingPointId);
            if (crlRecord == null) {
                result.put("Status", "1");
                result.put("Error", "CRL not yet generated");
                return Response.status(Response.Status.NOT_FOUND)
                        .entity(result.toString())
                        .type(MediaType.APPLICATION_JSON)
                        .build();
            }

            result.put("Status", "0");
            result.put("crlIssuingPoint", crlIssuingPointId);
            result.put("crlNumber", crlRecord.getCRLNumber().toString());
            result.put("crlSize", crlRecord.getCRLSize().longValue());

            if (crlDisplayType.equals("base64Encoded")) {
                byte[] crlbytes = crlRecord.getCRL();
                if (crlbytes != null) {
                    X509CRLImpl crl = new X509CRLImpl(crlbytes);
                    result.put("base64", Utils.base64encode(crl.getEncoded(), true));
                }
            }

        } catch (Exception e) {
            logger.error("CADisplayCRLResource: Error: {}", e.getMessage(), e);
            result.put("Status", "1");
            result.put("Error", e.getMessage());
            return Response.serverError()
                    .entity(result.toString())
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        return Response.ok(result.toString(), MediaType.APPLICATION_JSON).build();
    }
}
