//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.math.BigInteger;
import java.util.Enumeration;
import java.util.Vector;

import jakarta.inject.Inject;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CAEngineConfig;
import org.mozilla.jss.netscape.security.x509.X509CRLImpl;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.ca.CRLIssuingPoint;
import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.MetaInfo;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.dbs.DBException;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmscore.cert.CertUtils;
import com.netscape.cmscore.dbs.CRLIssuingPointRecord;
import com.netscape.cmscore.dbs.CRLRepository;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.ldap.CAPublisherProcessor;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestRepository;

/**
 * JAX-RS resource replacing the legacy UpdateDir CMSServlet.
 * Triggers LDAP directory update/publishing for CRLs, CA certificates,
 * and valid/expired/revoked certificates.
 *
 * Legacy URL: /agent/ca/updateDir
 */
@Path("agent/ca/updateDir")
public class CAUpdateDirResource {

    private static final Logger logger = LoggerFactory.getLogger(CAUpdateDirResource.class);

    @Inject
    CAEngineQuarkus engineQuarkus;

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response updateDir(
            @FormParam("updateAll") String updateAll,
            @FormParam("updateCRL") String updateCRL,
            @FormParam("updateCA") String updateCA,
            @FormParam("updateValid") String updateValid,
            @FormParam("validFrom") String validFrom,
            @FormParam("validTo") String validTo,
            @FormParam("updateExpired") String updateExpired,
            @FormParam("expiredFrom") String expiredFrom,
            @FormParam("expiredTo") String expiredTo,
            @FormParam("updateRevoked") String updateRevoked,
            @FormParam("revokedFrom") String revokedFrom,
            @FormParam("revokedTo") String revokedTo,
            @FormParam("checkFlag") String checkFlag,
            @FormParam("crlIssuingPoint") String crlIssuingPointId) {

        logger.info("CAUpdateDirResource: Processing directory update request");

        CAEngine engine = engineQuarkus.getEngine();
        CAEngineConfig cs = engine.getConfig();
        CertificateAuthority ca = engine.getCA();
        CAPublisherProcessor publisherProcessor = engine.getPublisherProcessor();
        CRLRepository crlRepository = engine.getCRLRepository();
        CertificateRepository certRepository = engine.getCertificateRepository();
        RequestRepository requestRepository = engine.getRequestRepository();

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode result = mapper.createObjectNode();

        if (publisherProcessor == null ||
                (!publisherProcessor.isCertPublishingEnabled() &&
                 !publisherProcessor.isCRLPublishingEnabled())) {
            result.put("Status", "1");
            result.put("Error", "Publishing module not enabled");
            return Response.ok(result.toString(), MediaType.APPLICATION_JSON).build();
        }

        boolean isClonedCA = false;
        try {
            String masterHost = cs.getString("master.ca.agent.host", "");
            String masterPort = cs.getString("master.ca.agent.port", "");
            if (masterHost != null && !masterHost.isEmpty() &&
                    masterPort != null && !masterPort.isEmpty()) {
                isClonedCA = true;
            }
        } catch (EBaseException e) {
            logger.warn("CAUpdateDirResource: Error reading clone config", e);
        }

        try {
            boolean doAll = isYes(updateAll);

            // Update CRL
            if (doAll || isYes(updateCRL)) {
                updateCRLPublishing(result, engine, crlRepository, publisherProcessor,
                        crlIssuingPointId, isClonedCA);
            }

            // Update CA cert
            if (doAll || isYes(updateCA)) {
                X509CertImpl caCert = ca.getSigningUnit().getCertImpl();
                try {
                    publisherProcessor.publishCACert(caCert);
                    result.put("caCertPublished", "Success");
                } catch (DBException e) {
                    result.put("caCertPublished", "Failure");
                    result.put("caCertError", e.getMessage());
                    logger.warn("CAUpdateDirResource: Error publishing CA cert", e);
                }
            }

            // Update valid certs
            if (doAll || isYes(updateValid)) {
                publishValidCerts(result, certRepository, requestRepository,
                        publisherProcessor, validFrom, validTo, isYes(checkFlag));
            }

            // Update expired certs
            if (doAll || isYes(updateExpired)) {
                unpublishCerts(result, certRepository, requestRepository,
                        publisherProcessor, "expired", expiredFrom, expiredTo, isYes(checkFlag));
            }

            // Update revoked certs
            if (doAll || isYes(updateRevoked)) {
                unpublishCerts(result, certRepository, requestRepository,
                        publisherProcessor, "revoked", revokedFrom, revokedTo, isYes(checkFlag));
            }

            result.put("Status", "0");

        } catch (Exception e) {
            logger.error("CAUpdateDirResource: Error: {}", e.getMessage(), e);
            result.put("Status", "1");
            result.put("Error", e.getMessage());
            return Response.serverError()
                    .entity(result.toString())
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        return Response.ok(result.toString(), MediaType.APPLICATION_JSON).build();
    }

    private void updateCRLPublishing(
            ObjectNode result,
            CAEngine engine,
            CRLRepository crlRepository,
            CAPublisherProcessor publisherProcessor,
            String crlIssuingPointId,
            boolean isClonedCA) throws EBaseException {

        // Validate CRL issuing point ID
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
            // Publish all issuing points
            if (isClonedCA && crlRepository != null) {
                Vector<String> ipNames = crlRepository.getIssuingPointsNames();
                if (ipNames != null) {
                    for (String ipName : ipNames) {
                        publishCRLForIssuingPoint(result, crlRepository, publisherProcessor,
                                ipName, null, isClonedCA);
                    }
                }
            } else {
                for (CRLIssuingPoint ip : engine.getCRLIssuingPoints()) {
                    publishCRLForIssuingPoint(result, crlRepository, publisherProcessor,
                            ip.getId(), ip, isClonedCA);
                }
            }
        } else {
            CRLIssuingPoint crlIssuingPoint = engine.getCRLIssuingPoint(crlIssuingPointId);
            publishCRLForIssuingPoint(result, crlRepository, publisherProcessor,
                    crlIssuingPointId, crlIssuingPoint, isClonedCA);
        }
    }

    private void publishCRLForIssuingPoint(
            ObjectNode result,
            CRLRepository crlRepository,
            CAPublisherProcessor publisherProcessor,
            String crlIssuingPointId,
            CRLIssuingPoint crlIssuingPoint,
            boolean isClonedCA) {

        SessionContext sc = SessionContext.getContext();
        sc.put(CRLIssuingPoint.SC_ISSUING_POINT_ID, crlIssuingPointId);
        sc.put(CRLIssuingPoint.SC_IS_DELTA_CRL, "false");

        CRLIssuingPointRecord crlRecord = null;
        try {
            if (crlRepository != null) {
                crlRecord = crlRepository.readCRLIssuingPointRecord(crlIssuingPointId);
            }
        } catch (EBaseException e) {
            logger.warn("CAUpdateDirResource: Error reading CRL record for {}", crlIssuingPointId, e);
        }

        if (crlRecord == null) {
            result.put("crlPublished", "Failure");
            result.put("crlError", "CRL not yet updated for " + crlIssuingPointId);
            return;
        }

        String publishDN = (crlIssuingPoint != null) ? crlIssuingPoint.getPublishDN() : null;
        byte[] crlbytes = crlRecord.getCRL();

        if (crlbytes == null) {
            result.put("crlPublished", "Failure");
            result.put("crlError", "CRL not yet updated");
            return;
        }

        X509CRLImpl crl = null;
        try {
            crl = new X509CRLImpl(crlbytes);
        } catch (Exception e) {
            logger.warn("CAUpdateDirResource: Error decoding CRL", e);
        }

        if (crl == null) {
            result.put("crlPublished", "Failure");
            result.put("crlError", "Failed to decode CRL");
            return;
        }

        try {
            if (publishDN != null) {
                publisherProcessor.publishCRL(publishDN, crl);
            } else {
                publisherProcessor.publishCRL(crl, crlIssuingPointId);
            }
            result.put("crlPublished", "Success");
        } catch (DBException e) {
            result.put("crlPublished", "Failure");
            result.put("crlError", e.getMessage());
            logger.warn("CAUpdateDirResource: Error publishing CRL", e);
        }

        // Handle delta CRL
        sc.put(CRLIssuingPoint.SC_IS_DELTA_CRL, "true");
        byte[] deltaCrlBytes = crlRecord.getDeltaCRL();

        if (deltaCrlBytes != null) {
            X509CRLImpl deltaCrl = null;
            try {
                deltaCrl = new X509CRLImpl(deltaCrlBytes);
            } catch (Exception e) {
                logger.warn("CAUpdateDirResource: Error decoding delta CRL", e);
            }

            boolean goodDelta = false;
            if (isClonedCA) {
                BigInteger crlNumber = crlRecord.getCRLNumber();
                BigInteger deltaNumber = crlRecord.getDeltaCRLNumber();
                Long deltaCRLSize = crlRecord.getDeltaCRLSize();
                if (deltaCRLSize != null && deltaCRLSize > -1 &&
                        crlNumber != null && deltaNumber != null &&
                        deltaNumber.compareTo(crlNumber) >= 0) {
                    goodDelta = true;
                }
            }

            if (deltaCrl != null && ((isClonedCA && goodDelta) ||
                    (crlIssuingPoint != null && crlIssuingPoint.isThisCurrentDeltaCRL(deltaCrl)))) {
                try {
                    if (publishDN != null) {
                        publisherProcessor.publishCRL(publishDN, deltaCrl);
                    } else {
                        publisherProcessor.publishCRL(deltaCrl, crlIssuingPointId);
                    }
                } catch (DBException e) {
                    logger.warn("CAUpdateDirResource: Error publishing delta CRL", e);
                }
            }
        }
    }

    private void publishValidCerts(
            ObjectNode result,
            CertificateRepository certRepo,
            RequestRepository requestRepository,
            CAPublisherProcessor publisherProcessor,
            String validFrom,
            String validTo,
            boolean checkFlag) throws EBaseException {

        if (certRepo == null) {
            result.put("validCertsPublished", "Failure");
            result.put("validCertsError", "Certificate repository is unavailable.");
            return;
        }

        String from = hexToDecimal(validFrom);
        String to = hexToDecimal(validTo);

        Enumeration<CertRecord> validCerts;
        if (checkFlag) {
            validCerts = certRepo.getValidNotPublishedCertificates(from, to);
        } else {
            validCerts = certRepo.getValidCertificates(from, to);
        }

        int published = 0;
        int total = 0;
        StringBuilder errors = new StringBuilder();

        if (validCerts != null) {
            while (validCerts.hasMoreElements()) {
                CertRecord certRecord = validCerts.nextElement();
                X509CertImpl cert = null;
                Object o = certRecord.getCertificate();
                if (o instanceof X509CertImpl) {
                    cert = (X509CertImpl) o;
                }

                Request r = getRequestForCert(certRecord, requestRepository);

                try {
                    total++;
                    SessionContext sc = SessionContext.getContext();
                    if (r == null) {
                        if (CertUtils.isEncryptionCert(cert))
                            sc.put("isEncryptionCert", "true");
                        else
                            sc.put("isEncryptionCert", "false");
                        publisherProcessor.publishCert(cert, null);
                    } else {
                        if (CertUtils.isEncryptionCert(cert))
                            r.setExtData("isEncryptionCert", "true");
                        else
                            r.setExtData("isEncryptionCert", "false");
                        publisherProcessor.publishCert(cert, r);
                    }
                    published++;
                } catch (Exception e) {
                    logger.warn("CAUpdateDirResource: Failed to publish cert 0x{}",
                            certRecord.getSerialNumber().toString(16), e);
                    errors.append("Failed to publish certificate: 0x")
                          .append(certRecord.getSerialNumber().toString(16))
                          .append(". ");
                }
            }
        }

        if (published > 0 && published == total) {
            result.put("validCertsPublished", "Success");
            result.put("validCertsError", published +
                    (published == 1 ? " valid certificate is" : " valid certificates are") +
                    " published in the directory.");
        } else if (total == 0) {
            result.put("validCertsPublished", "No");
        } else {
            result.put("validCertsPublished", "Failure");
            result.put("validCertsError", errors.toString());
        }
    }

    private void unpublishCerts(
            ObjectNode result,
            CertificateRepository certRepo,
            RequestRepository requestRepository,
            CAPublisherProcessor publisherProcessor,
            String type,
            String from,
            String to,
            boolean checkFlag) throws EBaseException {

        if (certRepo == null) {
            result.put(type + "CertsUnpublished", "Failure");
            result.put(type + "CertsError", "Certificate repository is unavailable.");
            return;
        }

        from = hexToDecimal(from);
        to = hexToDecimal(to);

        Enumeration<CertRecord> certs;
        if ("expired".equals(type)) {
            certs = checkFlag
                    ? certRepo.getExpiredPublishedCertificates(from, to)
                    : certRepo.getExpiredCertificates(from, to);
        } else {
            certs = checkFlag
                    ? certRepo.getRevokedPublishedCertificates(from, to)
                    : certRepo.getRevokedCertificates(from, to);
        }

        int unpublished = 0;
        int total = 0;
        StringBuilder errors = new StringBuilder();

        if (certs != null) {
            while (certs.hasMoreElements()) {
                CertRecord certRecord = certs.nextElement();
                X509CertImpl cert = null;
                Object o = certRecord.getCertificate();
                if (o instanceof X509CertImpl) {
                    cert = (X509CertImpl) o;
                }

                Request r = getRequestForCert(certRecord, requestRepository);

                try {
                    total++;
                    if (r == null) {
                        publisherProcessor.unpublishCert(cert, null);
                    } else {
                        publisherProcessor.unpublishCert(cert, r);
                    }
                    unpublished++;
                } catch (Exception e) {
                    logger.warn("CAUpdateDirResource: Failed to unpublish cert 0x{}",
                            certRecord.getSerialNumber().toString(16), e);
                    errors.append("Failed to unpublish certificate: 0x")
                          .append(certRecord.getSerialNumber().toString(16))
                          .append(". ");
                }
            }
        }

        if (unpublished > 0 && unpublished == total) {
            result.put(type + "CertsUnpublished", "Success");
            result.put(type + "CertsError", unpublished +
                    (unpublished == 1 ? " " + type + " certificate is" : " " + type + " certificates are") +
                    " unpublished in the directory.");
        } else if (total == 0) {
            result.put(type + "CertsUnpublished", "No");
        } else {
            result.put(type + "CertsUnpublished", "Failure");
            result.put(type + "CertsError", errors.toString());
        }
    }

    private Request getRequestForCert(CertRecord certRecord, RequestRepository requestRepository) {
        try {
            MetaInfo metaInfo = (MetaInfo) certRecord.get(CertRecord.ATTR_META_INFO);
            if (metaInfo != null) {
                String ridString = (String) metaInfo.get(CertRecord.META_REQUEST_ID);
                if (ridString != null) {
                    RequestId rid = new RequestId(ridString);
                    return requestRepository.readRequest(rid);
                }
            }
        } catch (EBaseException e) {
            logger.warn("CAUpdateDirResource: Error reading request for cert", e);
        }
        return null;
    }

    private boolean isYes(String value) {
        return value != null && value.equalsIgnoreCase("yes");
    }

    private String hexToDecimal(String hex) {
        if (hex != null && hex.startsWith("0x")) {
            return new BigInteger(hex.substring(2), 16).toString();
        }
        return hex;
    }
}
