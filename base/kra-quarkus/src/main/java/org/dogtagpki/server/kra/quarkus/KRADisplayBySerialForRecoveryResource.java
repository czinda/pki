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
import org.dogtagpki.server.kra.KRAEngineConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.dbs.KeyRecord;
import com.netscape.cmscore.dbs.KeyRepository;
import com.netscape.kra.KeyRecoveryAuthority;

/**
 * JAX-RS resource replacing the legacy DisplayBySerialForRecovery CMSServlet.
 * Displays key record details and initiates the key recovery process
 * by generating a recovery ID.
 *
 * The original servlet provides key details along with:
 * - The number of required recovery agents
 * - The keySplitting configuration
 * - A recoveryID token for the recovery workflow
 * - Optional publicKeyData pass-through
 *
 * Legacy URL: /agent/kra/displayBySerialForRecovery
 */
@Path("agent/kra/displayBySerialForRecovery")
public class KRADisplayBySerialForRecoveryResource {

    private static final Logger logger = LoggerFactory.getLogger(KRADisplayBySerialForRecoveryResource.class);

    @Inject
    KRAEngineQuarkus engineQuarkus;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response displayBySerialForRecovery(
            @QueryParam("serialNumber") String serialNumberStr,
            @QueryParam("publicKeyData") String publicKeyData) {

        logger.info("KRADisplayBySerialForRecoveryResource: Displaying key for recovery");

        KRAEngine engine = engineQuarkus.getEngine();
        KRAEngineConfig cs = engine.getConfig();
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

            // Include recovery workflow metadata
            result.put("noOfRequiredAgents", kra.getNoOfRequiredAgents());

            try {
                result.put("keySplitting", cs.getString("kra.keySplitting"));
            } catch (EBaseException e) {
                logger.debug("KRADisplayBySerialForRecoveryResource: keySplitting config not found");
            }

            if (publicKeyData != null) {
                result.put("publicKeyData", publicKeyData);
            }

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
            result.put("serialNumber", serialNumber.toString());
            result.put("serialNumberInHex", serialNumber.toString(16));
            result.put("ownerName", keyRecord.getOwnerName());
            result.put("algorithm", keyRecord.getAlgorithm());
            result.put("keySize", keyRecord.getKeySize());
            result.put("state", keyRecord.getState().toString());
            result.put("publicKey", keyRecord.getPublicKeyData() != null ? "available" : "unavailable");

            // Generate a recovery identifier for the recovery workflow
            result.put("recoveryID", kra.getRecoveryID());

        } catch (NumberFormatException e) {
            logger.error("KRADisplayBySerialForRecoveryResource: Invalid serial number format: {}",
                    serialNumberStr, e);
            result.put("Status", "1");
            result.put("Error", "Invalid serial number format");
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(result.toString())
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        } catch (Exception e) {
            logger.error("KRADisplayBySerialForRecoveryResource: Error: {}", e.getMessage(), e);
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
