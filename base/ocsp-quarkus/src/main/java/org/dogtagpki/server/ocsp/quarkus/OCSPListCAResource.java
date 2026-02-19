//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ocsp.quarkus;

import java.math.BigInteger;
import java.util.Date;
import java.util.Enumeration;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.ocsp.OCSPEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Node;

import com.netscape.certsrv.ocsp.IDefStore;
import com.netscape.cmscore.dbs.CRLIssuingPointRecord;
import com.netscape.cmsutil.xml.XMLObject;
import com.netscape.ocsp.OCSPAuthority;

/**
 * JAX-RS resource replacing the legacy ListCAServlet CMSServlet.
 * Lists all CAs that the OCSP responder can service.
 * Legacy URL: /agent/ocsp/listCAs
 */
@Path("agent/ocsp/listCAs")
public class OCSPListCAResource {

    private static final Logger logger = LoggerFactory.getLogger(OCSPListCAResource.class);

    @Inject
    OCSPEngineQuarkus engineQuarkus;

    @GET
    @Produces(MediaType.APPLICATION_XML)
    public Response listCAs() {

        logger.info("OCSPListCAResource: Listing CAs");

        OCSPEngine engine = engineQuarkus.getEngine();
        OCSPAuthority ocspAuthority = engine.getOCSP();
        IDefStore defStore = ocspAuthority.getDefaultStore();

        try {
            XMLObject xmlObj = new XMLObject();
            Node root = xmlObj.createRoot("XMLResponse");
            xmlObj.addItemToContainer(root, "Status", "0");
            xmlObj.addItemToContainer(root, "StateCount",
                    Integer.toString(defStore.getStateCount()));

            Node casNode = xmlObj.createContainer(root, "CAs");

            Enumeration<CRLIssuingPointRecord> recs =
                    defStore.searchAllCRLIssuingPointRecord(100);

            while (recs.hasMoreElements()) {
                CRLIssuingPointRecord rec = recs.nextElement();
                Node caNode = xmlObj.createContainer(casNode, "CA");

                String thisId = rec.getId();
                xmlObj.addItemToContainer(caNode, "Id", thisId);

                Date thisUpdate = rec.getThisUpdate();
                xmlObj.addItemToContainer(caNode, "ThisUpdate",
                        thisUpdate != null ? thisUpdate.toString() : "UNKNOWN");

                Date nextUpdate = rec.getNextUpdate();
                xmlObj.addItemToContainer(caNode, "NextUpdate",
                        nextUpdate != null ? nextUpdate.toString() : "UNKNOWN");

                Long rc = rec.getCRLSize();
                if (rc == null || rc.longValue() == -1) {
                    xmlObj.addItemToContainer(caNode, "NumRevoked", "UNKNOWN");
                } else {
                    xmlObj.addItemToContainer(caNode, "NumRevoked", rc.toString());
                }

                BigInteger crlNumber = rec.getCRLNumber();
                if (crlNumber == null || crlNumber.equals(new BigInteger("-1"))) {
                    xmlObj.addItemToContainer(caNode, "CRLNumber", "UNKNOWN");
                } else {
                    xmlObj.addItemToContainer(caNode, "CRLNumber", crlNumber.toString());
                }

                xmlObj.addItemToContainer(caNode, "ReqCount",
                        Long.toString(defStore.getReqCount(thisId)));
            }

            byte[] cb = xmlObj.toByteArray();
            return Response.ok(new String(cb), MediaType.APPLICATION_XML).build();

        } catch (Exception e) {
            logger.error("OCSPListCAResource: {}", e.getMessage(), e);
            return Response.serverError().build();
        }
    }
}
