//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ocsp.quarkus;

import java.security.cert.X509CRLEntry;
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
import org.mozilla.jss.netscape.security.x509.X509CRLImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Node;

import com.netscape.certsrv.ocsp.IDefStore;
import com.netscape.cmscore.dbs.CRLIssuingPointRecord;
import com.netscape.cmsutil.xml.XMLObject;
import com.netscape.ocsp.OCSPAuthority;

/**
 * JAX-RS resource replacing the legacy CheckCertServlet CMSServlet.
 * Checks the revocation status of a specific certificate.
 * Legacy URL: /agent/ocsp/checkCert
 */
@Path("agent/ocsp/checkCert")
public class OCSPCheckCertResource {

    private static final Logger logger = LoggerFactory.getLogger(OCSPCheckCertResource.class);

    private static final String STATUS_GOOD = "good";
    private static final String STATUS_REVOKED = "revoked";
    private static final String STATUS_UNKNOWN = "unknown";

    @Inject
    OCSPEngineQuarkus engineQuarkus;

    @POST
    @Produces(MediaType.APPLICATION_XML)
    public Response checkCert(@FormParam("cert") String b64) {

        logger.info("OCSPCheckCertResource: Checking certificate");

        OCSPEngine engine = engineQuarkus.getEngine();
        OCSPAuthority ocspAuthority = engine.getOCSP();
        IDefStore defStore = ocspAuthority.getDefaultStore();

        if (b64 == null || b64.isEmpty()) {
            return errorResponse("Missing certificate");
        }

        if (b64.indexOf(Cert.HEADER) == -1 || b64.indexOf(Cert.FOOTER) == -1) {
            return errorResponse("Missing certificate header or footer");
        }

        X509Certificate cert;
        try {
            cert = Cert.mapCert(b64);
        } catch (Exception e) {
            return errorResponse("Error decoding certificate");
        }

        if (cert == null) {
            return errorResponse("Error decoding certificate");
        }

        String issuerDN = cert.getIssuerDN().getName();
        String subjectDN = cert.getSubjectDN().getName();
        String serialNo = "0x" + cert.getSerialNumber().toString(16);
        String status;

        try {
            CRLIssuingPointRecord pt = defStore.readCRLIssuingPoint(issuerDN);
            X509CRLImpl crl = new X509CRLImpl(pt.getCRL());
            X509CRLEntry crlentry = crl.getRevokedCertificate(cert.getSerialNumber());

            if (crlentry == null) {
                status = defStore.isNotFoundGood() ? STATUS_GOOD : STATUS_UNKNOWN;
            } else {
                status = STATUS_REVOKED;
            }
        } catch (Exception e) {
            status = STATUS_UNKNOWN;
        }

        logger.info("OCSPCheckCertResource: Certificate status for {} {}: {}",
                issuerDN, serialNo, status);

        try {
            XMLObject xmlObj = new XMLObject();
            Node root = xmlObj.createRoot("XMLResponse");
            xmlObj.addItemToContainer(root, "Status", "0");
            xmlObj.addItemToContainer(root, "CertStatus", status);
            xmlObj.addItemToContainer(root, "IssuerDN", issuerDN);
            xmlObj.addItemToContainer(root, "SubjectDN", subjectDN);
            xmlObj.addItemToContainer(root, "SerialNo", serialNo);
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
