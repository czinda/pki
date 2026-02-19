//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ocsp.quarkus;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.util.Date;

import jakarta.inject.Inject;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.ocsp.OCSPEngine;
import org.dogtagpki.server.ocsp.OCSPEngineConfig;
import org.dogtagpki.util.cert.CertUtil;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.X509CRLImpl;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509ExtensionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.ocsp.IDefStore;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.dbs.CRLIssuingPointRecord;
import com.netscape.cmscore.dbs.RepositoryRecord;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.ocsp.OCSPAuthority;

/**
 * JAX-RS resource replacing the legacy AddCRLServlet CMSServlet.
 * Updates the OCSP responder with a new CRL from a CA.
 * Legacy URL: /agent/ocsp/addCRL
 */
@Path("agent/ocsp/addCRL")
public class OCSPAddCRLResource {

    private static final Logger logger = LoggerFactory.getLogger(OCSPAddCRLResource.class);

    @Inject
    OCSPEngineQuarkus engineQuarkus;

    @POST
    @Produces(MediaType.TEXT_PLAIN)
    public Response addCRL(
            @FormParam("crl") String b64,
            @QueryParam("noui") String nouiParam) {

        logger.info("OCSPAddCRLResource: Adding CRL");

        OCSPEngine engine = engineQuarkus.getEngine();
        OCSPEngineConfig cs = engine.getConfig();
        Auditor auditor = engine.getAuditor();
        String auditCRLNum = ILogger.SIGNED_AUDIT_EMPTY_VALUE;

        boolean noUI = "true".equals(nouiParam);
        boolean CRLFetched = false;

        try {
            if (b64 == null) {
                auditor.log(CMS.getLogMessage(
                        AuditEvent.CRL_RETRIEVAL, null, ILogger.FAILURE, auditCRLNum));
                return textResponse("status=1\nerror=Missing CRL\n");
            }

            if (b64.indexOf(CertUtil.CRL_HEADER) == -1 || b64.indexOf(CertUtil.CRL_FOOTER) == -1) {
                auditor.log(CMS.getLogMessage(
                        AuditEvent.CRL_RETRIEVAL, null, ILogger.FAILURE, auditCRLNum));
                return textResponse("status=1\nerror=Missing CRL header or footer\n");
            }

            OCSPAuthority ocspAuthority = engine.getOCSP();
            IDefStore defStore = ocspAuthority.getDefaultStore();

            // Parse CRL
            X509CRLImpl crl;
            try {
                crl = mapCRL(b64);
                BigInteger crlNum = crl.getCRLNumber();
                if (crlNum != null) {
                    auditCRLNum = crlNum.toString();
                }
                auditor.log(CMS.getLogMessage(
                        AuditEvent.CRL_RETRIEVAL, null, ILogger.SUCCESS, auditCRLNum));
                CRLFetched = true;
            } catch (Exception e) {
                logger.error("OCSPAddCRLResource: Unable to parse CRL: {}", e.getMessage(), e);
                auditor.log(CMS.getLogMessage(
                        AuditEvent.CRL_RETRIEVAL, null, ILogger.FAILURE, auditCRLNum));
                return textResponse("status=1\nerror=Unable to parse CRL\n");
            }

            logger.info("OCSPAddCRLResource: Issuer DN: {}", crl.getIssuerDN().getName());

            // Verify CRL issuing point exists
            CRLIssuingPointRecord pt;
            try {
                pt = defStore.readCRLIssuingPoint(crl.getIssuerDN().getName());
            } catch (Exception e) {
                logger.error("OCSPAddCRLResource: Unable to retrieve CRL issuing point: {}", e.getMessage(), e);
                auditor.log(CMS.getLogMessage(
                        AuditEvent.CRL_VALIDATION, null, ILogger.FAILURE));
                return textResponse("status=1\nerror=Unknown CRL issuing point\n");
            }

            // Verify CRL signature
            byte[] caCertData = pt.getCACert();
            if (caCertData != null) {
                try {
                    CryptoManager cmanager = CryptoManager.getInstance();
                    X509CertImpl caCert = new X509CertImpl(caCertData);
                    String tokenName = cs.getString("ocsp.crlVerify.token", CryptoUtil.INTERNAL_TOKEN_NAME);
                    CryptoToken savedToken = cmanager.getThreadToken();
                    CryptoToken verToken = CryptoUtil.getCryptoToken(tokenName);
                    boolean tokenSwitched = false;

                    try {
                        if (!savedToken.getName().equals(verToken.getName())) {
                            cmanager.setThreadToken(verToken);
                            tokenSwitched = true;
                        }

                        org.mozilla.jss.crypto.X509Certificate jssCert =
                                cmanager.importCACertPackage(caCert.getEncoded());
                        crl.verify(jssCert.getPublicKey(), "Mozilla-JSS");

                        auditor.log(CMS.getLogMessage(
                                AuditEvent.CRL_VALIDATION, null, ILogger.SUCCESS));
                    } finally {
                        if (tokenSwitched) {
                            cmanager.setThreadToken(savedToken);
                        }
                    }
                } catch (Exception e) {
                    logger.error("OCSPAddCRLResource: Failed to verify CRL: {}", e.getMessage(), e);
                    auditor.log(CMS.getLogMessage(
                            AuditEvent.CRL_VALIDATION, null, ILogger.FAILURE));
                    return textResponse("status=1\nerror=CRL verification failed\n");
                }
            }

            // Check if CRL is newer
            if (pt.getThisUpdate() != null &&
                    pt.getThisUpdate().getTime() >= crl.getThisUpdate().getTime()) {
                logger.warn("OCSPAddCRLResource: Received CRL is not newer than current CRL");
                return textResponse("status=1\nerror=Sent CRL is not newer than the current CRL\n");
            }

            // Reject delta CRLs
            if (crl.isDeltaCRL()) {
                logger.warn("OCSPAddCRLResource: Delta CRLs are not supported");
                return textResponse("status=1\nerror=Delta CRLs are not supported.\n");
            }

            // Commit CRL
            logger.info("OCSPAddCRLResource: Committing CRL");

            RepositoryRecord repRec = defStore.createRepositoryRecord();
            repRec.set(RepositoryRecord.ATTR_SERIALNO,
                    new BigInteger(Long.toString(crl.getThisUpdate().getTime())));
            try {
                defStore.addRepository(
                        crl.getIssuerDN().getName(),
                        Long.toString(crl.getThisUpdate().getTime()),
                        repRec);
            } catch (Exception e) {
                logger.error("OCSPAddCRLResource: {}", e.getMessage(), e);
            }

            if (defStore.waitOnCRLUpdate()) {
                defStore.updateCRL(crl);
            } else {
                Thread uct = new Thread(() -> {
                    try {
                        X509CRL fullCrl = crl;
                        if (!((X509CRLImpl) fullCrl).areEntriesIncluded()) {
                            fullCrl = new X509CRLImpl(((X509CRLImpl) fullCrl).getEncoded());
                        }
                        defStore.updateCRL(fullCrl);
                    } catch (CRLException | X509ExtensionException | EBaseException e) {
                        logger.error("OCSPAddCRLResource: CRL update thread error: {}", e.getMessage());
                    }
                });
                uct.start();
            }

            return textResponse("status=0");

        } catch (Exception e) {
            logger.error("OCSPAddCRLResource: {}", e.getMessage(), e);
            if (!CRLFetched) {
                auditor.log(CMS.getLogMessage(
                        AuditEvent.CRL_RETRIEVAL, null, ILogger.FAILURE, auditCRLNum));
            }
            return textResponse("status=1\nerror=" + e.getMessage() + "\n");
        }
    }

    private X509CRLImpl mapCRL(String mime64) throws IOException {
        mime64 = Cert.stripCRLBrackets(mime64.trim());
        byte[] rawPub = Utils.base64decode(mime64);
        try {
            return new X509CRLImpl(rawPub, false);
        } catch (Exception e) {
            throw new IOException(e.toString());
        }
    }

    private Response textResponse(String body) {
        return Response.ok(body, "application/text").build();
    }
}
