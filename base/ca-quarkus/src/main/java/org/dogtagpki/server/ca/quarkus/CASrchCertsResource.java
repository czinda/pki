//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.util.Enumeration;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;

/**
 * JAX-RS resource replacing the legacy SrchCerts CMSServlet.
 * Searches certificates matching a query filter.
 * Legacy URL: /ee/ca/srchCerts
 */
@Path("ee/ca/srchCerts")
public class CASrchCertsResource {

    private static final Logger logger = LoggerFactory.getLogger(CASrchCertsResource.class);
    private static final int MAX_RESULTS = 1000;

    @Inject
    CAEngineQuarkus engineQuarkus;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response searchCerts(
            @QueryParam("queryCertFilter") String filter,
            @QueryParam("maxResults") String maxResultsStr,
            @QueryParam("timeLimit") String timeLimitStr) {

        logger.info("CASrchCertsResource: Searching certificates");

        CAEngine engine = engineQuarkus.getEngine();
        CertificateRepository certDB = engine.getCertificateRepository();

        int maxResults = MAX_RESULTS;
        int timeLimit = 10;

        try {
            if (maxResultsStr != null) maxResults = Integer.parseInt(maxResultsStr);
            if (timeLimitStr != null) timeLimit = Integer.parseInt(timeLimitStr);
        } catch (NumberFormatException e) {
            // use defaults
        }

        if (maxResults > MAX_RESULTS) maxResults = MAX_RESULTS;

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode result = mapper.createObjectNode();
        ArrayNode certsArray = mapper.createArrayNode();

        if (filter == null || filter.isEmpty()) {
            result.put("Status", "1");
            result.put("Error", "Missing search filter");
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(result.toString())
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        try {
            Enumeration<CertRecord> e = certDB.searchCertificates(filter, maxResults, timeLimit);
            int count = 0;

            while (e != null && e.hasMoreElements() && count < maxResults) {
                CertRecord certRecord = e.nextElement();
                X509CertImpl cert = certRecord.getCertificate();

                ObjectNode certNode = mapper.createObjectNode();
                certNode.put("serialNumber", cert.getSerialNumber().toString(16));
                certNode.put("subjectDN", cert.getSubjectName().toString());
                certNode.put("issuerDN", cert.getIssuerName().toString());
                certNode.put("status", certRecord.getStatus());
                certNode.put("notBefore", cert.getNotBefore().getTime());
                certNode.put("notAfter", cert.getNotAfter().getTime());
                certsArray.add(certNode);
                count++;
            }

            result.put("Status", "0");
            result.put("totalCount", count);
            result.set("certificates", certsArray);

        } catch (Exception e) {
            logger.error("CASrchCertsResource: Error: {}", e.getMessage(), e);
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
