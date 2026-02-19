//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.pkcs.ContentInfo;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.pkcs.SignerInfo;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.CRLExtensions;
import org.mozilla.jss.netscape.security.x509.CRLReasonExtension;
import org.mozilla.jss.netscape.security.x509.Extension;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.dbs.DBRecordNotFoundException;
import com.netscape.cmscore.cert.CertUtils;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.dbs.RevocationInfo;

/**
 * JAX-RS resource replacing the legacy CADisplayBySerial CMSServlet.
 * Displays detailed information about a certificate identified by its
 * serial number. Returns certificate details as JSON including the
 * base64-encoded certificate, PKCS#7 chain, fingerprints, and
 * revocation information.
 * Legacy URL: /ee/ca/displayBySerial
 */
@Path("ee/ca/displayBySerial")
public class CADisplayBySerialResource {

    private static final Logger logger = LoggerFactory.getLogger(CADisplayBySerialResource.class);

    @Inject
    CAEngineQuarkus engineQuarkus;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response displayBySerial(@QueryParam("serialNumber") String serialNumberStr) {

        logger.info("CADisplayBySerialResource: Displaying certificate by serial number");

        if (serialNumberStr == null || serialNumberStr.trim().isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"Error\":\"Missing serialNumber parameter\"}")
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        CAEngine engine = engineQuarkus.getEngine();
        CertificateRepository certDB = engine.getCertificateRepository();
        CertificateAuthority ca = engine.getCA();

        BigInteger serialNumber;
        try {
            serialNumber = parseSerialNumber(serialNumberStr.trim());
        } catch (NumberFormatException e) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"Error\":\"Invalid serial number format\"}")
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode result = mapper.createObjectNode();

        try {
            CertRecord rec = certDB.readCertificateRecord(serialNumber);
            if (rec == null) {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity("{\"Error\":\"Certificate not found\"}")
                        .type(MediaType.APPLICATION_JSON)
                        .build();
            }

            X509CertImpl cert = rec.getCertificate();
            if (cert == null) {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity("{\"Error\":\"Certificate data not available\"}")
                        .type(MediaType.APPLICATION_JSON)
                        .build();
            }

            // Basic certificate info
            result.put("serialNumber", serialNumber.toString(16));
            result.put("subjectDN", cert.getSubjectName().toString());
            result.put("issuerDN", cert.getIssuerName().toString());
            result.put("status", rec.getStatus());
            result.put("notBefore", cert.getNotBefore().getTime());
            result.put("notAfter", cert.getNotAfter().getTime());
            result.put("version", cert.getVersion());
            result.put("authorityid", "ca");

            // Base64-encoded certificate
            byte[] certBytes = cert.getEncoded();
            result.put("certChainBase64", Utils.base64encode(certBytes, true));

            // Certificate fingerprints
            try {
                String fingerprints = CertUtils.getFingerPrints(cert);
                if (fingerprints != null && !fingerprints.isEmpty()) {
                    result.put("certFingerprint", fingerprints);
                }
            } catch (Exception e) {
                logger.warn("CADisplayBySerialResource: Error computing fingerprints: {}", e.getMessage());
            }

            // Revocation info
            RevocationInfo revocationInfo = rec.getRevocationInfo();
            if (revocationInfo != null) {
                CRLExtensions crlExts = revocationInfo.getCRLEntryExtensions();
                if (crlExts != null) {
                    Enumeration<Extension> enumx = crlExts.getElements();
                    int reason = 0;
                    while (enumx.hasMoreElements()) {
                        Extension ext = enumx.nextElement();
                        if (ext instanceof CRLReasonExtension crlReasonExtension) {
                            reason = crlReasonExtension.getReason().getCode();
                        }
                    }
                    result.put("revocationReason", reason);
                }
            }

            // PKCS#7 chain
            try {
                X509Certificate[] caCerts = ca.getCACertChain().getChain();
                X509CertImpl[] certsInChain;

                if (caCerts != null) {
                    boolean certIsCA = false;
                    for (X509Certificate caCert : caCerts) {
                        if (cert.equals(caCert)) {
                            certIsCA = true;
                            break;
                        }
                    }
                    certsInChain = new X509CertImpl[certIsCA ? caCerts.length : caCerts.length + 1];
                    certsInChain[0] = cert;
                    for (int i = 0; i < caCerts.length; i++) {
                        if (!cert.equals(caCerts[i])) {
                            certsInChain[i + 1] = (X509CertImpl) caCerts[i];
                        }
                    }
                } else {
                    certsInChain = new X509CertImpl[] { cert };
                }

                PKCS7 p7 = new PKCS7(new AlgorithmId[0],
                        new ContentInfo(new byte[0]),
                        certsInChain,
                        new SignerInfo[0]);
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                p7.encodeSignedData(bos, false);
                result.put("pkcs7ChainBase64", Utils.base64encode(bos.toByteArray(), true));

            } catch (Exception e) {
                logger.warn("CADisplayBySerialResource: Error forming PKCS7: {}", e.getMessage());
            }

            result.put("Status", "0");

        } catch (DBRecordNotFoundException e) {
            return Response.status(Response.Status.NOT_FOUND)
                    .entity("{\"Error\":\"Certificate serial number not found: 0x" + serialNumber.toString(16) + "\"}")
                    .type(MediaType.APPLICATION_JSON)
                    .build();

        } catch (Exception e) {
            logger.error("CADisplayBySerialResource: Error retrieving certificate: {}", e.getMessage(), e);
            return Response.serverError()
                    .entity("{\"Error\":\"" + e.getMessage() + "\"}")
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        return Response.ok(result.toString(), MediaType.APPLICATION_JSON).build();
    }

    private BigInteger parseSerialNumber(String serialNumString) {
        if (serialNumString.startsWith("0x") || serialNumString.startsWith("0X")) {
            return new BigInteger(serialNumString.substring(2), 16);
        }
        return new BigInteger(serialNumString);
    }
}
