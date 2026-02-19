//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ocsp.quarkus;

import java.math.BigInteger;
import java.security.cert.X509Certificate;

import jakarta.inject.Inject;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.ocsp.OCSPEngine;
import org.mozilla.jss.netscape.security.util.Cert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Node;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.OCSPAddCARequestEvent;
import com.netscape.certsrv.logging.event.OCSPAddCARequestProcessedEvent;
import com.netscape.certsrv.ocsp.IDefStore;
import com.netscape.cmscore.dbs.CRLIssuingPointRecord;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmsutil.xml.XMLObject;
import com.netscape.ocsp.OCSPAuthority;

/**
 * JAX-RS resource replacing the legacy AddCAServlet CMSServlet.
 * Adds a CA certificate to the OCSP responder's list of known CAs.
 * Legacy URL: /agent/ocsp/addCA
 */
@Path("agent/ocsp/addCA")
public class OCSPAddCAResource {

    private static final Logger logger = LoggerFactory.getLogger(OCSPAddCAResource.class);
    private static final BigInteger BIG_ZERO = new BigInteger("0");
    private static final Long MINUS_ONE = Long.valueOf(-1);

    @Inject
    OCSPEngineQuarkus engineQuarkus;

    @POST
    @Produces(MediaType.APPLICATION_XML)
    public Response addCA(@FormParam("cert") String b64) {

        logger.info("OCSPAddCAResource: Adding CA");

        OCSPEngine engine = engineQuarkus.getEngine();
        Auditor auditor = engine.getAuditor();
        String auditCASubjectDN = ILogger.SIGNED_AUDIT_EMPTY_VALUE;

        if (b64 == null || b64.isEmpty()) {
            auditor.log(OCSPAddCARequestEvent.createFailureEvent(null));
            return errorResponse("Missing CA certificate");
        }

        String auditCA = Cert.normalizeCertStr(Cert.stripCertBrackets(b64.trim()));
        auditor.log(OCSPAddCARequestEvent.createSuccessEvent(null, auditCA));

        if (b64.indexOf(Cert.HEADER) == -1) {
            auditor.log(OCSPAddCARequestProcessedEvent.createFailureEvent(null, auditCASubjectDN));
            return errorResponse("Missing certificate header");
        }
        if (b64.indexOf(Cert.FOOTER) == -1) {
            auditor.log(OCSPAddCARequestProcessedEvent.createFailureEvent(null, auditCASubjectDN));
            return errorResponse("Missing certificate footer");
        }

        OCSPAuthority ocspAuthority = engine.getOCSP();
        IDefStore defStore = ocspAuthority.getDefaultStore();

        X509Certificate leafCert = null;
        X509Certificate[] certs = null;

        try {
            X509Certificate cert = Cert.mapCert(b64);
            if (cert != null) {
                certs = new X509Certificate[1];
                certs[0] = cert;
                leafCert = cert;
                auditCASubjectDN = leafCert.getSubjectDN().getName();
            }
        } catch (Exception e) {
            // try PKCS7 chain
        }

        if (certs == null) {
            try {
                certs = Cert.mapCertFromPKCS7(b64);
                if (certs[0].getSubjectDN().getName().equals(certs[0].getIssuerDN().getName())) {
                    leafCert = certs[certs.length - 1];
                } else {
                    leafCert = certs[0];
                }
                auditCASubjectDN = leafCert.getSubjectDN().getName();
            } catch (Exception e) {
                auditor.log(OCSPAddCARequestProcessedEvent.createFailureEvent(null, auditCASubjectDN));
                return errorResponse("Error encoding CA certificate chain");
            }
        }

        if (certs != null && certs.length > 0) {
            CRLIssuingPointRecord rec = defStore.createCRLIssuingPointRecord(
                    leafCert.getSubjectDN().getName(),
                    BIG_ZERO, MINUS_ONE, null, null);

            try {
                rec.set(CRLIssuingPointRecord.ATTR_CA_CERT, leafCert.getEncoded());
            } catch (Exception e) {
                auditor.log(OCSPAddCARequestProcessedEvent.createFailureEvent(null, auditCASubjectDN));
                return errorResponse("Error encoding CA certificate");
            }

            try {
                defStore.addCRLIssuingPoint(leafCert.getSubjectDN().getName(), rec);
            } catch (EBaseException e) {
                auditor.log(OCSPAddCARequestProcessedEvent.createFailureEvent(null, auditCASubjectDN));
                return errorResponse("Error adding CA: " + e.getMessage());
            }

            logger.info("OCSPAddCAResource: Added CA certificate {}", leafCert.getSubjectDN().getName());
            auditor.log(OCSPAddCARequestProcessedEvent.createSuccessEvent(null, auditCASubjectDN));
        }

        try {
            XMLObject xmlObj = new XMLObject();
            Node root = xmlObj.createRoot("XMLResponse");
            xmlObj.addItemToContainer(root, "Status", "0");
            xmlObj.addItemToContainer(root, "CASubjectDN", auditCASubjectDN);
            byte[] cb = xmlObj.toByteArray();
            return Response.ok(new String(cb), MediaType.APPLICATION_XML).build();
        } catch (Exception e) {
            return Response.serverError().build();
        }
    }

    private Response errorResponse(String message) {
        try {
            XMLObject xmlObj = new XMLObject();
            Node root = xmlObj.createRoot("XMLResponse");
            xmlObj.addItemToContainer(root, "Status", "1");
            xmlObj.addItemToContainer(root, "Error", message);
            byte[] cb = xmlObj.toByteArray();
            return Response.serverError()
                    .type(MediaType.APPLICATION_XML)
                    .entity(new String(cb))
                    .build();
        } catch (Exception e) {
            return Response.serverError().build();
        }
    }
}
