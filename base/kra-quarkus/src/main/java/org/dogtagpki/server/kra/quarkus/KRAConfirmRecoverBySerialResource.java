//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

import java.math.BigInteger;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.kra.KRAEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.cmscore.dbs.KeyRecord;
import com.netscape.cmscore.dbs.KeyRepository;
import com.netscape.kra.KeyRecoveryAuthority;

/**
 * JAX-RS resource replacing the legacy ConfirmRecoverBySerial CMSServlet.
 * Shows key information and the number of required recovery agents
 * so agents can confirm before proceeding with key recovery.
 *
 * Legacy URL: /agent/kra/confirmRecoverBySerial
 */
@Path("agent/kra/confirmRecoverBySerial")
public class KRAConfirmRecoverBySerialResource {

    private static final Logger logger = LoggerFactory.getLogger(KRAConfirmRecoverBySerialResource.class);

    @Inject
    KRAEngineQuarkus engineQuarkus;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response confirmRecoverBySerial(@QueryParam("serialNumber") String serialNumberStr) {

        logger.info("KRAConfirmRecoverBySerialResource: Confirming recovery");

        KRAEngine engine = engineQuarkus.getEngine();
        KeyRepository keyDB = engine.getKeyRepository();
        KeyRecoveryAuthority kra = engine.getKRA();

        if (serialNumberStr == null || serialNumberStr.isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"Status\":\"1\",\"Error\":\"Missing serialNumber parameter\"}")
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode result = mapper.createObjectNode();

        try {
            BigInteger serialNumber;
            serialNumberStr = serialNumberStr.trim();
            if (serialNumberStr.startsWith("0x") || serialNumberStr.startsWith("0X")) {
                serialNumber = new BigInteger(serialNumberStr.substring(2), 16);
            } else {
                serialNumber = new BigInteger(serialNumberStr);
            }

            result.put("serialNumber", serialNumber.toString());
            result.put("serialNumberInHex", serialNumber.toString(16));

            // Include the number of required recovery agents
            result.put("noOfRequiredAgents", kra.getNoOfRequiredAgents());

            KeyRecord keyRecord = keyDB.readKeyRecord(serialNumber);
            if (keyRecord == null) {
                result.put("Status", "1");
                result.put("Error", "Key not found");
                return Response.status(Response.Status.NOT_FOUND)
                        .entity(result.toString())
                        .type(MediaType.APPLICATION_JSON)
                        .build();
            }

            result.put("Status", "0");
            result.put("ownerName", keyRecord.getOwnerName());
            result.put("algorithm", keyRecord.getAlgorithm());
            result.put("keySize", keyRecord.getKeySize());
            result.put("state", keyRecord.getState().toString());
            result.put("publicKey", keyRecord.getPublicKeyData() != null ? "available" : "unavailable");

        } catch (NumberFormatException e) {
            logger.error("KRAConfirmRecoverBySerialResource: Invalid serial number format: {}",
                    serialNumberStr, e);
            result.put("Status", "1");
            result.put("Error", "Invalid serial number format");
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(result.toString())
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        } catch (Exception e) {
            logger.error("KRAConfirmRecoverBySerialResource: Error: {}", e.getMessage(), e);
            result.put("Status", "1");
            result.put("Error", e.getMessage());
            return Response.serverError()
                    .entity(result.toString())
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        return Response.ok(result.toString(), MediaType.APPLICATION_JSON).build();
    }
}
