//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ocsp.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.ocsp.OCSPEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Node;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.logging.event.OCSPRemoveCARequestEvent;
import com.netscape.certsrv.logging.event.OCSPRemoveCARequestProcessedEvent;
import com.netscape.certsrv.ocsp.IDefStore;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmsutil.xml.XMLObject;
import com.netscape.ocsp.OCSPAuthority;

/**
 * JAX-RS resource replacing the legacy RemoveCAServlet CMSServlet.
 * Removes a CA from the OCSP responder's list.
 * Legacy URL: /agent/ocsp/removeCA
 */
@Path("agent/ocsp/removeCA")
public class OCSPRemoveCAResource {

    private static final Logger logger = LoggerFactory.getLogger(OCSPRemoveCAResource.class);

    @Inject
    OCSPEngineQuarkus engineQuarkus;

    @POST
    @Produces(MediaType.APPLICATION_XML)
    public Response removeCA(@QueryParam("caID") String caID) {

        logger.info("OCSPRemoveCAResource: Removing CA: {}", caID);

        OCSPEngine engine = engineQuarkus.getEngine();
        Auditor auditor = engine.getAuditor();

        if (caID == null || caID.isEmpty()) {
            auditor.log(OCSPRemoveCARequestEvent.createFailureEvent(null));
            return errorResponse("Missing CA ID");
        }

        auditor.log(OCSPRemoveCARequestEvent.createSuccessEvent(null, caID));

        OCSPAuthority ocspAuthority = engine.getOCSP();
        IDefStore defStore = ocspAuthority.getDefaultStore();

        try {
            defStore.deleteCRLIssuingPointRecord(caID);
        } catch (EBaseException e) {
            auditor.log(OCSPRemoveCARequestProcessedEvent.createFailureEvent(null, caID));
            logger.error("OCSPRemoveCAResource: Error deleting CRL IssuingPoint {}: {}", caID, e.getMessage(), e);
            return errorResponse("Error removing CA: " + e.getMessage());
        }

        logger.info("OCSPRemoveCAResource: CRL IssuingPoint for CA successfully removed: {}", caID);
        auditor.log(OCSPRemoveCARequestProcessedEvent.createSuccessEvent(null, caID));

        try {
            XMLObject xmlObj = new XMLObject();
            Node root = xmlObj.createRoot("XMLResponse");
            xmlObj.addItemToContainer(root, "Status", "0");
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
