//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.quarkus;

import java.math.BigInteger;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.DatabaseConfig;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.dbs.Repository;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmsutil.json.JSONObject;

/**
 * Abstract base JAX-RS resource replacing the legacy UpdateNumberRange CMSServlet.
 * Transfers a portion of this instance's number range to a clone.
 * Used during clone deployment to allocate serial/request/replica ranges.
 *
 * Each subsystem extends this with a concrete @Path annotation and
 * repository lookup.
 */
public abstract class UpdateNumberRangeResourceBase {

    private static final Logger logger = LoggerFactory.getLogger(UpdateNumberRangeResourceBase.class);
    private static final String SUCCESS = "0";

    protected abstract CMSEngine getEngine();

    protected abstract Repository getRepository(String type) throws EBaseException;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response updateNumberRange(@QueryParam("type") String type) {

        logger.info("UpdateNumberRangeResourceBase: type={}", type);

        CMSEngine engine = getEngine();
        Auditor auditor = engine.getAuditor();
        String auditParams = "source;;updateNumberRange+type;;" + type;

        try {
            EngineConfig cs = engine.getConfig();
            DatabaseConfig dbConfig = cs.getDatabaseConfig();

            Repository repo = getRepository(type);

            // checkRanges for replicaID - we do this each time a replica is created
            if ("replicaId".equals(type)) {
                logger.debug("UpdateNumberRangeResourceBase: Checking replica number ranges");
                repo.checkRanges();
            }

            int radix = repo.getRadix();
            String endNumConfig = null;
            String cloneNumConfig = null;
            String nextEndConfig = null;

            if ("request".equals(type)) {
                endNumConfig = "endRequestNumber";
                cloneNumConfig = "requestCloneTransferNumber";
                nextEndConfig = "nextEndRequestNumber";
            } else if ("serialNo".equals(type)) {
                endNumConfig = "endSerialNumber";
                cloneNumConfig = "serialCloneTransferNumber";
                nextEndConfig = "nextEndSerialNumber";
            } else if ("replicaId".equals(type)) {
                endNumConfig = "endReplicaNumber";
                cloneNumConfig = "replicaCloneTransferNumber";
                nextEndConfig = "nextEndReplicaNumber";
            }

            BigInteger endNum;
            BigInteger transferSize;
            if (repo.getIDGenerator() == Repository.IDGenerator.LEGACY_2) {
                endNum = dbConfig.getBigInteger(endNumConfig);
                transferSize = dbConfig.getBigInteger(cloneNumConfig);
            } else {
                String endNumStr = dbConfig.getString(endNumConfig);
                endNum = new BigInteger(endNumStr, radix);
                String transferSizeStr = dbConfig.getString(cloneNumConfig, "");
                transferSize = new BigInteger(transferSizeStr, radix);
            }

            logger.info("UpdateNumberRangeResourceBase: dbs.{}: {}", endNumConfig, endNum);
            logger.info("UpdateNumberRangeResourceBase: dbs.{}: {}", cloneNumConfig, transferSize);

            BigInteger beginNum = endNum.subtract(transferSize).add(BigInteger.ONE);
            logger.info("UpdateNumberRangeResourceBase: Begin number: {}", beginNum);

            synchronized (repo) {
                BigInteger nextSerial = repo.peekNextSerialNumber();
                if (nextSerial == null) {
                    String msg = "Current range depleted but no next range available.";
                    logger.error(msg);
                    throw new RuntimeException(msg);
                }

                logger.info("UpdateNumberRangeResourceBase: Current range: {}..{}", nextSerial, endNum);

                if (beginNum.compareTo(nextSerial) < 0) {
                    if (repo.getIDGenerator() == Repository.IDGenerator.LEGACY_2) {
                        endNum = dbConfig.getBigInteger(nextEndConfig);
                    } else {
                        endNum = new BigInteger(dbConfig.getString(nextEndConfig, ""), radix);
                    }
                    BigInteger newEndNum = endNum.subtract(transferSize);

                    logger.info("UpdateNumberRangeResourceBase: Transferring from next range end");
                    repo.setNextMaxSerial(newEndNum);
                    String strNewEndNum = newEndNum.toString(radix);
                    if (repo.getIDGenerator() == Repository.IDGenerator.LEGACY_2 && radix == Repository.HEX) {
                        strNewEndNum = "0x" + strNewEndNum;
                    }
                    dbConfig.putString(nextEndConfig, strNewEndNum);
                    beginNum = newEndNum.add(BigInteger.ONE);
                } else {
                    BigInteger newEndNum = beginNum.subtract(BigInteger.ONE);
                    repo.setMaxSerial(newEndNum);
                    String newValStr = newEndNum.toString(radix);
                    if (repo.getIDGenerator() == Repository.IDGenerator.LEGACY_2 && radix == Repository.HEX) {
                        newValStr = "0x" + newValStr;
                    }
                    dbConfig.putString(endNumConfig, newValStr);
                    logger.info("UpdateNumberRangeResourceBase: New current range: {}..{}", nextSerial, newEndNum);
                }

                logger.info("UpdateNumberRangeResourceBase: Transferring range: {}..{}", beginNum, endNum);
            }

            if (beginNum == null) {
                logger.error("UpdateNumberRangeResourceBase: Missing begin number");
                auditor.log(CMS.getLogMessage(
                        AuditEvent.CONFIG_SERIAL_NUMBER, null, ILogger.FAILURE, auditParams));
                return Response.serverError().build();
            }

            if ("replicaId".equals(type)) {
                repo.setEnableSerialMgmt(true);
            }

            JSONObject jsonObj = new JSONObject();
            ObjectNode responseNode = jsonObj.getMapper().createObjectNode();
            responseNode.put("Status", SUCCESS);
            if (repo.getIDGenerator() == Repository.IDGenerator.LEGACY_2 && radix == Repository.HEX) {
                responseNode.put("beginNumber", "0x" + beginNum.toString(radix));
                responseNode.put("endNumber", "0x" + endNum.toString(radix));
            } else {
                responseNode.put("beginNumber", beginNum.toString(radix));
                responseNode.put("endNumber", endNum.toString(radix));
            }
            jsonObj.getRootNode().set("Response", responseNode);

            cs.commit(false);

            auditParams += "+beginNumber;;" + beginNum.toString(radix) +
                    "+endNumber;;" + endNum.toString(radix);
            auditor.log(CMS.getLogMessage(
                    AuditEvent.CONFIG_SERIAL_NUMBER, null, ILogger.SUCCESS, auditParams));

            return Response.ok(new String(jsonObj.toByteArray()), MediaType.APPLICATION_JSON).build();

        } catch (Exception e) {
            logger.error("UpdateNumberRangeResourceBase: Unable to update number range: {}", e.getMessage(), e);
            auditor.log(CMS.getLogMessage(
                    AuditEvent.CONFIG_SERIAL_NUMBER, null, ILogger.FAILURE, auditParams));
            return Response.serverError()
                    .type(MediaType.APPLICATION_JSON)
                    .entity("{\"Error\":\"Unable to update number range: " + e.getMessage() + "\"}")
                    .build();
        }
    }
}
