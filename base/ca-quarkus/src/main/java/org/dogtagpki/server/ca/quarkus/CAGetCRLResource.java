//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.security.cert.CRLException;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.X509CRLImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.ca.CertificateAuthority;
import com.netscape.cmscore.dbs.CRLIssuingPointRecord;
import com.netscape.cmscore.dbs.CRLRepository;

/**
 * JAX-RS resource replacing the legacy GetCRL CMSServlet.
 * Retrieves CRL for a Certificate Authority.
 *
 * Legacy URL: /ee/ca/getCRL
 */
@Path("ee/ca/getCRL")
public class CAGetCRLResource {

    private static final Logger logger = LoggerFactory.getLogger(CAGetCRLResource.class);

    @Inject
    CAEngineQuarkus engineQuarkus;

    @GET
    public Response getCRL(
            @QueryParam("op") String op,
            @QueryParam("crlIssuingPoint") String crlIssuingPointId,
            @QueryParam("mimeType") String mimeType,
            @QueryParam("crlDisplayType") String crlDisplayType) throws Exception {

        logger.debug("CAGetCRLResource.getCRL(): op={}, crlIssuingPoint={}",
                op, crlIssuingPointId);

        if (op == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Missing 'op' parameter")
                    .build();
        }

        CAEngine engine = engineQuarkus.getEngine();

        if (crlIssuingPointId == null || crlIssuingPointId.isEmpty()) {
            crlIssuingPointId = CertificateAuthority.PROP_MASTER_CRL;
        }

        CRLRepository crlRepository = engine.getCRLRepository();
        CRLIssuingPointRecord crlRecord = crlRepository.readCRLIssuingPointRecord(crlIssuingPointId);

        if (crlRecord == null) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity("CRL issuing point not found: " + crlIssuingPointId)
                    .build();
        }

        byte[] crlBytes = crlRecord.getCRL();
        if (crlBytes == null) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity("CRL not available for issuing point: " + crlIssuingPointId)
                    .build();
        }

        if (op.equals("importCRL")) {
            // Return CRL in PEM format
            String crlPEM = Utils.base64encode(crlBytes, true);
            return Response.ok(crlPEM, "application/x-pkcs7-crl").build();

        } else if (op.equals("getCRL") || op.equals("downloadBIN")) {
            // Return binary DER CRL
            if (mimeType == null) {
                mimeType = "application/x-pkcs7-crl";
            }
            return Response.ok(crlBytes, mimeType)
                    .header("Content-Disposition",
                            "attachment; filename=crl-" + crlIssuingPointId + ".crl")
                    .build();

        } else if (op.equals("displayCRL")) {
            // Return CRL details as JSON
            try {
                X509CRLImpl crl = new X509CRLImpl(crlBytes);
                String json = "{" +
                        "\"issuer\":\"" + escapeJson(crl.getIssuerDN().toString()) + "\"," +
                        "\"thisUpdate\":\"" + crl.getThisUpdate() + "\"," +
                        "\"nextUpdate\":\"" + crl.getNextUpdate() + "\"," +
                        "\"size\":" + (crl.getRevokedCertificates() != null ?
                                crl.getRevokedCertificates().size() : 0) +
                        "}";
                return Response.ok(json, "application/json").build();
            } catch (CRLException e) {
                logger.error("CAGetCRLResource: Error parsing CRL", e);
                return Response.serverError().entity("Error parsing CRL").build();
            }

        } else {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Invalid operation: " + op)
                    .build();
        }
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
