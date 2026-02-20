//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.math.BigInteger;
import java.util.Vector;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CAEngineConfig;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.ca.CRLIssuingPoint;
import com.netscape.ca.CertificateAuthority;
import com.netscape.cmscore.dbs.CRLIssuingPointRecord;
import com.netscape.cmscore.dbs.CRLRepository;

/**
 * JAX-RS resource replacing the legacy GetInfo CMSServlet.
 * Returns detailed information about CA CRL processing.
 * Legacy URL: /ee/ca/getInfo
 */
@Path("ee/ca/getInfo")
public class CAGetInfoResource {

    private static final Logger logger = LoggerFactory.getLogger(CAGetInfoResource.class);

    @Inject
    CAEngineQuarkus engineQuarkus;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getInfo() {

        logger.info("CAGetInfoResource: Getting CA info");

        CAEngine engine = engineQuarkus.getEngine();
        CAEngineConfig cs = engine.getConfig();
        CRLRepository crlRepository = engine.getCRLRepository();
        CertificateAuthority ca = engine.getCA();

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode result = mapper.createObjectNode();

        if (ca == null) {
            result.put("Status", "1");
            result.put("Error", "CA not available");
            return Response.serverError()
                    .entity(result.toString())
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        StringBuilder crlIssuingPoints = new StringBuilder();
        StringBuilder crlNumbers = new StringBuilder();
        StringBuilder deltaNumbers = new StringBuilder();
        StringBuilder crlSizes = new StringBuilder();
        StringBuilder deltaSizes = new StringBuilder();
        StringBuilder crlDescriptions = new StringBuilder();
        StringBuilder crlSplits = new StringBuilder();
        StringBuilder recentChanges = new StringBuilder();
        StringBuilder crlTesting = new StringBuilder();
        boolean isDeltaCRLEnabled = false;

        String masterHost = "";
        String masterPort = "";
        try {
            masterHost = cs.getString("master.ca.agent.host", "");
            masterPort = cs.getString("master.ca.agent.port", "");
        } catch (Exception e) {
            // ignore
        }

        boolean isClone = masterHost != null && !masterHost.isEmpty() &&
                           masterPort != null && !masterPort.isEmpty();

        if (isClone) {
            Vector<String> ipNames;
            try {
                ipNames = crlRepository.getIssuingPointsNames();
            } catch (Exception e) {
                logger.error("CAGetInfoResource: Error getting CRL issuing points", e);
                result.put("Status", "1");
                result.put("Error", "Error getting CRL issuing points: " + e.getMessage());
                return Response.serverError()
                        .entity(result.toString())
                        .type(MediaType.APPLICATION_JSON)
                        .build();
            }
            for (int i = 0; i < ipNames.size(); i++) {
                String ipName = ipNames.elementAt(i);
                CRLIssuingPointRecord crlRecord = null;
                try {
                    crlRecord = crlRepository.readCRLIssuingPointRecord(ipName);
                } catch (Exception e) {
                    // ignore
                }
                if (crlRecord != null) {
                    appendSeparated(crlIssuingPoints, ipName);

                    BigInteger crlNumber = crlRecord.getCRLNumber();
                    appendSeparated(crlNumbers, crlNumber != null ? crlNumber.toString() : "");

                    appendSeparated(crlSizes, crlRecord.getCRLSize() != null ?
                            crlRecord.getCRLSize().toString() : "-1");

                    long dSize = crlRecord.getDeltaCRLSize() != null ?
                            crlRecord.getDeltaCRLSize().longValue() : -1;
                    appendSeparated(deltaSizes, String.valueOf(dSize));

                    BigInteger deltaNumber = crlRecord.getDeltaCRLNumber();
                    if (deltaNumber != null && dSize > -1) {
                        appendSeparated(deltaNumbers, deltaNumber.toString());
                        isDeltaCRLEnabled = true;
                    } else {
                        appendSeparated(deltaNumbers, "0");
                    }

                    appendSeparated(recentChanges, "-, -, -");
                    appendSeparated(crlTesting, "0");
                }
            }
        } else {
            for (CRLIssuingPoint ip : engine.getCRLIssuingPoints()) {
                if (ip.isCRLIssuingPointEnabled()) {
                    appendSeparated(crlIssuingPoints, ip.getId());

                    BigInteger crlNumber = ip.getCRLNumber();
                    appendSeparated(crlNumbers, crlNumber != null ? crlNumber.toString() : "");

                    BigInteger deltaNumber = ip.getDeltaCRLNumber();
                    appendSeparated(deltaNumbers, deltaNumber != null ? deltaNumber.toString() : "");

                    appendSeparated(crlSizes, String.valueOf(ip.getCRLSize()));
                    appendSeparated(deltaSizes, String.valueOf(ip.getDeltaCRLSize()));
                    appendSeparated(crlDescriptions, ip.getDescription());

                    if (ip.isCRLUpdateInProgress() == CRLIssuingPoint.CRL_PUBLISHING_STARTED) {
                        appendSeparated(recentChanges, "Publishing CRL #" + ip.getCRLNumber());
                    } else if (ip.isCRLUpdateInProgress() == CRLIssuingPoint.CRL_UPDATE_STARTED) {
                        appendSeparated(recentChanges, "Creating CRL #" + ip.getNextCRLNumber());
                    } else {
                        appendSeparated(recentChanges,
                                ip.getNumberOfRecentlyRevokedCerts() + ", " +
                                ip.getNumberOfRecentlyUnrevokedCerts() + ", " +
                                ip.getNumberOfRecentlyExpiredCerts());
                    }

                    isDeltaCRLEnabled |= ip.isDeltaCRLEnabled();

                    if (crlSplits.length() > 0) crlSplits.append("+");
                    Vector<Long> splits = ip.getSplitTimes();
                    for (int i = 0; i < splits.size(); i++) {
                        crlSplits.append(splits.elementAt(i));
                        if (i + 1 < splits.size()) crlSplits.append(",");
                    }

                    appendSeparated(crlTesting, ip.isCRLCacheTestingEnabled() ? "1" : "0");
                }
            }
        }

        result.put("crlIssuingPoints", crlIssuingPoints.toString());
        result.put("crlDescriptions", crlDescriptions.toString());
        result.put("crlNumbers", crlNumbers.toString());
        result.put("deltaNumbers", deltaNumbers.toString());
        result.put("crlSizes", crlSizes.toString());
        result.put("deltaSizes", deltaSizes.toString());
        result.put("crlSplits", crlSplits.toString());
        result.put("crlTesting", crlTesting.toString());
        result.put("isDeltaCRLEnabled", isDeltaCRLEnabled);
        result.put("master_host", masterHost);
        result.put("master_port", masterPort);
        result.put("masterCRLIssuingPoint", CertificateAuthority.PROP_MASTER_CRL);

        CRLIssuingPoint ip0 = engine.getCRLIssuingPoint(CertificateAuthority.PROP_MASTER_CRL);
        if (ip0 != null) {
            result.put("defaultAlgorithm", ip0.getSigningAlgorithm());
        }

        if (recentChanges.length() > 0) {
            result.put("recentChanges", recentChanges.toString());
        }

        String[] allAlgorithms = ca.getCASigningAlgorithms();
        if (allAlgorithms == null) {
            allAlgorithms = AlgorithmId.ALL_SIGNING_ALGORITHMS;
        }
        result.put("validAlgorithms", String.join("+", allAlgorithms));

        result.put("Status", "0");
        return Response.ok(result.toString(), MediaType.APPLICATION_JSON).build();
    }

    private void appendSeparated(StringBuilder sb, String value) {
        if (sb.length() > 0) sb.append("+");
        sb.append(value);
    }
}
