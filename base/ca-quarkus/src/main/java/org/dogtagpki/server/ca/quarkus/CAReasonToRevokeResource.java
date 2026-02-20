//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

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
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;

/**
 * JAX-RS resource replacing the legacy ReasonToRevoke CMSServlet.
 * Displays certificate details and available revocation reasons.
 * Legacy URL: /agent/ca/reasonToRevoke
 */
@Path("agent/ca/reasonToRevoke")
public class CAReasonToRevokeResource {

    private static final Logger logger = LoggerFactory.getLogger(CAReasonToRevokeResource.class);

    @Inject
    CAEngineQuarkus engineQuarkus;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response reasonToRevoke(@QueryParam("serialNumber") String serialNumberStr) {

        logger.info("CAReasonToRevokeResource: Getting revocation reasons for certificate");

        CAEngine engine = engineQuarkus.getEngine();
        CertificateRepository certDB = engine.getCertificateRepository();

        if (serialNumberStr == null || serialNumberStr.isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"Error\":\"Missing serialNumber parameter\"}")
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode result = mapper.createObjectNode();

        try {
            java.math.BigInteger serialNumber;
            serialNumberStr = serialNumberStr.trim();
            if (serialNumberStr.startsWith("0x") || serialNumberStr.startsWith("0X")) {
                serialNumber = new java.math.BigInteger(serialNumberStr.substring(2), 16);
            } else {
                serialNumber = new java.math.BigInteger(serialNumberStr);
            }

            CertRecord certRecord = certDB.readCertificateRecord(serialNumber);
            if (certRecord == null) {
                result.put("Status", "1");
                result.put("Error", "Certificate not found");
                return Response.status(Response.Status.NOT_FOUND)
                        .entity(result.toString())
                        .type(MediaType.APPLICATION_JSON)
                        .build();
            }

            X509CertImpl cert = certRecord.getCertificate();
            result.put("Status", "0");
            result.put("serialNumber", serialNumber.toString(16));
            result.put("subjectDN", cert.getSubjectName().toString());
            result.put("issuerDN", cert.getIssuerName().toString());
            result.put("notBefore", cert.getNotBefore().toString());
            result.put("notAfter", cert.getNotAfter().toString());
            result.put("certStatus", certRecord.getStatus());

        } catch (Exception e) {
            logger.error("CAReasonToRevokeResource: Error: {}", e.getMessage(), e);
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
