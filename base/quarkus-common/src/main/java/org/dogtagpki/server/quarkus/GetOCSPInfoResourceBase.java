//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.quarkus;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.certsrv.ocsp.IOCSPService;

/**
 * Abstract base JAX-RS resource replacing the legacy GetOCSPInfo CMSServlet.
 * Returns OCSP responder statistics including request counts,
 * processing times, signing times, lookup times, and throughput.
 * Each subsystem that provides OCSP services (CA, OCSP) extends
 * this with a concrete @Path annotation.
 *
 * Legacy URL pattern: /ee/{subsystem}/getOCSPInfo
 */
public abstract class GetOCSPInfoResourceBase {

    private static final Logger logger = LoggerFactory.getLogger(GetOCSPInfoResourceBase.class);

    /**
     * Return the IOCSPService implementation for the subsystem.
     * The CA's CertificateAuthority and the OCSP's OCSPAuthority
     * both implement IOCSPService.
     */
    protected abstract IOCSPService getOCSPService();

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getOCSPInfo() {

        logger.info("GetOCSPInfoResourceBase: Getting OCSP info");

        IOCSPService ocspService = getOCSPService();

        if (ocspService == null) {
            return Response.status(Response.Status.SERVICE_UNAVAILABLE)
                    .entity("{\"Error\":\"OCSP service not available\"}")
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode result = mapper.createObjectNode();

        long numReq = ocspService.getNumOCSPRequest();
        long totalSec = ocspService.getOCSPRequestTotalTime();
        long totalSignSec = ocspService.getOCSPTotalSignTime();
        long totalLookupSec = ocspService.getOCSPTotalLookupTime();
        long totalData = ocspService.getOCSPTotalData();

        result.put("numReq", numReq);
        result.put("totalSec", totalSec);
        result.put("totalSignSec", totalSignSec);
        result.put("totalLookupSec", totalLookupSec);
        result.put("totalData", totalData);

        // Compute requests per second
        long reqPerSec = 0;
        if (totalSec != 0) {
            reqPerSec = (numReq * 1000) / totalSec;
        }
        result.put("ReqSec", reqPerSec);

        result.put("Status", "0");

        return Response.ok(result.toString(), MediaType.APPLICATION_JSON).build();
    }
}
