//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.cmscore.dbs.CertificateRepository;

/**
 * JAX-RS resource replacing the legacy RevocationServlet CMSServlet.
 * First step in revoking a certificate - looks up the cert and returns
 * details for confirmation before actual revocation.
 * Legacy URL: /ee/ca/revocation
 */
@Path("ee/ca/revocation")
public class CARevocationResource {

    private static final Logger logger = LoggerFactory.getLogger(CARevocationResource.class);

    @Inject
    CAEngineQuarkus engineQuarkus;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getRevocationInfo(
            @QueryParam("serialNo") String serialNoStr,
            @QueryParam("reasonCode") String reasonCodeStr) {

        logger.info("CARevocationResource: Getting revocation info");

        CAEngine engine = engineQuarkus.getEngine();
        CertificateRepository cr = engine.getCertificateRepository();

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode result = mapper.createObjectNode();

        if (serialNoStr == null || serialNoStr.isEmpty()) {
            result.put("Status", "1");
            result.put("Error", "Missing serialNo parameter");
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(result.toString())
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        try {
            BigInteger serialNo;
            serialNoStr = serialNoStr.trim();
            if (serialNoStr.startsWith("0x") || serialNoStr.startsWith("0X")) {
                serialNo = new BigInteger(serialNoStr.substring(2), 16);
            } else {
                serialNo = new BigInteger(serialNoStr);
            }

            X509CertImpl cert = cr.getX509Certificate(serialNo);
            if (cert == null) {
                result.put("Status", "1");
                result.put("Error", "Certificate not found");
                return Response.status(Response.Status.NOT_FOUND)
                        .entity(result.toString())
                        .type(MediaType.APPLICATION_JSON)
                        .build();
            }

            // Find all unrevoked certs for this subject
            X509CertImpl[] certsToRevoke = cr.getX509Certificates(
                    cert.getSubjectName().toString(),
                    CertificateRepository.ALL_UNREVOKED_CERTS);

            // Verify the requested cert is among unrevoked certs
            boolean authorized = false;
            if (certsToRevoke != null) {
                for (X509CertImpl c : certsToRevoke) {
                    if (cert.getSerialNumber().equals(c.getSerialNumber())) {
                        authorized = true;
                        break;
                    }
                }
            }

            if (!authorized) {
                result.put("Status", "1");
                result.put("Error", "Certificate is already revoked or not found");
                return Response.status(Response.Status.CONFLICT)
                        .entity(result.toString())
                        .type(MediaType.APPLICATION_JSON)
                        .build();
            }

            result.put("Status", "0");
            result.put("serialNumber", cert.getSerialNumber().toString(16));
            result.put("serialNumberDecimal", cert.getSerialNumber().toString());

            int reasonCode = 0;
            if (reasonCodeStr != null) {
                try {
                    reasonCode = Integer.parseInt(reasonCodeStr);
                } catch (NumberFormatException e) {
                    // use default
                }
            }
            result.put("reason", reasonCode);

            // Include base64 encoded cert
            try {
                byte[] certBytes = cert.getEncoded();
                result.put("b64eCertificate", Utils.base64encode(certBytes, true));
            } catch (CertificateEncodingException e) {
                logger.warn("CARevocationResource: Failed to encode certificate", e);
            }

            // Include list of certs eligible for revocation
            ArrayNode certsArray = mapper.createArrayNode();
            if (certsToRevoke != null) {
                result.put("totalRecordCount", certsToRevoke.length);
                result.put("verifiedRecordCount", certsToRevoke.length);

                for (X509CertImpl c : certsToRevoke) {
                    ObjectNode certNode = mapper.createObjectNode();
                    certNode.put("serialNumber", c.getSerialNumber().toString(16));
                    certNode.put("serialNumberDecimal", c.getSerialNumber().toString());
                    certNode.put("subject", c.getSubjectDN().toString());
                    certNode.put("validNotBefore", c.getNotBefore().getTime() / 1000);
                    certNode.put("validNotAfter", c.getNotAfter().getTime() / 1000);
                    certsArray.add(certNode);
                }
            } else {
                result.put("totalRecordCount", 0);
                result.put("verifiedRecordCount", 0);
            }
            result.set("certs", certsArray);

        } catch (Exception e) {
            logger.error("CARevocationResource: Error: {}", e.getMessage(), e);
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
