//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

import java.math.BigInteger;
import java.util.Date;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.kra.KRAEngine;
import org.mozilla.jss.netscape.security.util.PrettyPrintFormat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.MetaInfo;
import com.netscape.cmscore.dbs.KeyRecord;
import com.netscape.cmscore.dbs.KeyRepository;

/**
 * JAX-RS resource replacing the legacy DisplayBySerial CMSServlet.
 * Displays a specific key archival record by serial number.
 *
 * Legacy URL: /agent/kra/displayBySerial
 */
@Path("agent/kra/displayBySerial")
public class KRADisplayBySerialResource {

    private static final Logger logger = LoggerFactory.getLogger(KRADisplayBySerialResource.class);

    @Inject
    KRAEngineQuarkus engineQuarkus;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response displayBySerial(@QueryParam("serialNumber") String serialNumber) {

        logger.debug("KRADisplayBySerialResource.displayBySerial({})", serialNumber);

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode result = mapper.createObjectNode();

        try {
            if (serialNumber == null || serialNumber.trim().isEmpty()) {
                result.put("error", "Missing required parameter: serialNumber");
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(result.toString())
                        .build();
            }

            BigInteger seqNum;
            try {
                seqNum = new BigInteger(serialNumber.trim());
            } catch (NumberFormatException e) {
                result.put("error", "Invalid serial number format: " + serialNumber);
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(result.toString())
                        .build();
            }

            KRAEngine engine = engineQuarkus.getEngine();
            KeyRepository keyDB = engine.getKeyRepository();
            KeyRecord rec = keyDB.readKeyRecord(seqNum);

            if (rec == null) {
                result.put("error", "Key record not found for serial number: " + serialNumber);
                return Response.status(Response.Status.NOT_FOUND)
                        .entity(result.toString())
                        .build();
            }

            fillKeyRecordInfo(rec, result);

            return Response.ok(result.toString(), MediaType.APPLICATION_JSON).build();

        } catch (EBaseException e) {
            logger.error("KRADisplayBySerialResource: Failed to read key record: {}", e.getMessage(), e);
            result.put("error", e.getMessage());
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(result.toString())
                    .build();
        }
    }

    /**
     * Fill key record fields into JSON object node, mirroring
     * KeyRecordParser.fillRecordIntoArg().
     */
    private void fillKeyRecordInfo(KeyRecord rec, ObjectNode node) throws EBaseException {
        node.put("state", rec.getState().toString());
        node.put("ownerName", rec.getOwnerName());
        node.put("serialNumber", rec.getSerialNumber().toString(10));
        node.put("serialNumberInHex", rec.getSerialNumber().toString(16));
        node.put("keyAlgorithm", rec.getAlgorithm());

        PrettyPrintFormat pp = new PrettyPrintFormat(":");
        byte[] publicKeyData = rec.getPublicKeyData();
        if (publicKeyData != null) {
            node.put("publicKey", pp.toHexString(publicKeyData, 0, 20));
        }

        Integer keySize = rec.getKeySize();
        node.put("keyLength", keySize != null ? keySize : 512);

        MetaInfo metaInfo = rec.getMetaInfo();
        if (metaInfo != null) {
            String curve = (String) metaInfo.get("EllipticCurve");
            if (curve != null) {
                node.put("EllipticCurve", curve);
            }
        }

        node.put("archivedBy", rec.getArchivedBy());

        Date createTime = rec.getCreateTime();
        if (createTime != null) {
            node.put("archivedOn", createTime.getTime() / 1000);
        }

        Date[] dateOfRevocation = rec.getDateOfRevocation();
        if (dateOfRevocation != null) {
            node.put("recoveredBy", "null");
            node.put("recoveredOn", "null");
        }
    }
}
