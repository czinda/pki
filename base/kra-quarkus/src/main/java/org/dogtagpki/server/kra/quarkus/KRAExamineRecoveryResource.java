//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

import java.math.BigInteger;
import java.util.Date;
import java.util.Hashtable;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.kra.KRAEngine;
import org.dogtagpki.server.kra.KRAEngineConfig;
import org.mozilla.jss.netscape.security.util.PrettyPrintFormat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.MetaInfo;
import com.netscape.cmscore.dbs.KeyRecord;
import com.netscape.cmscore.dbs.KeyRepository;
import com.netscape.kra.KeyRecoveryAuthority;

/**
 * JAX-RS resource replacing the legacy ExamineRecovery CMSServlet.
 * Shows details of a key recovery request for agent review, including
 * the associated key record information.
 *
 * Legacy URL: /agent/kra/examineRecovery
 */
@Path("agent/kra/examineRecovery")
public class KRAExamineRecoveryResource {

    private static final Logger logger = LoggerFactory.getLogger(KRAExamineRecoveryResource.class);

    @Inject
    KRAEngineQuarkus engineQuarkus;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response examineRecovery(@QueryParam("recoveryID") String recoveryID) {

        logger.debug("KRAExamineRecoveryResource.examineRecovery({})", recoveryID);

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode result = mapper.createObjectNode();

        try {
            if (recoveryID == null || recoveryID.trim().isEmpty()) {
                result.put("error", "Missing required parameter: recoveryID");
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(result.toString())
                        .build();
            }

            KRAEngine engine = engineQuarkus.getEngine();
            KRAEngineConfig cs = engine.getConfig();
            KeyRecoveryAuthority kra = engine.getKRA();
            KeyRepository keyDB = engine.getKeyRepository();

            // Add key splitting config info
            try {
                result.put("keySplitting", cs.getString("kra.keySplitting"));
            } catch (EBaseException e) {
                logger.debug("KRAExamineRecoveryResource: keySplitting config not found");
            }

            Hashtable<String, Object> params = kra.getRecoveryParams(recoveryID);

            if (params == null) {
                logger.error("KRAExamineRecoveryResource: No recovery token found for {}", recoveryID);
                result.put("error", "No recovery token found for recovery ID: " + recoveryID);
                return Response.status(Response.Status.NOT_FOUND)
                        .entity(result.toString())
                        .build();
            }

            String keyID = (String) params.get("keyID");
            result.put("serialNumber", keyID);
            result.put("recoveryID", recoveryID);

            // Read the associated key record and fill in details
            KeyRecord rec = keyDB.readKeyRecord(new BigInteger(keyID));
            fillKeyRecordInfo(rec, result);

            return Response.ok(result.toString(), MediaType.APPLICATION_JSON).build();

        } catch (EBaseException e) {
            logger.error("KRAExamineRecoveryResource: Failed to examine recovery: {}", e.getMessage(), e);
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
        if (rec == null) {
            return;
        }

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
