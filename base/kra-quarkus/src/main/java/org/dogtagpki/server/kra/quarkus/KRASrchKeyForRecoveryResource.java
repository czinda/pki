//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

import java.util.Enumeration;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.kra.KRAEngine;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.cmscore.dbs.KeyRecord;
import com.netscape.cmscore.dbs.KeyRepository;
import com.netscape.cmsutil.ldap.LDAPUtil;
import com.netscape.kra.KeyRecoveryAuthority;

/**
 * JAX-RS resource replacing the legacy SrchKeyForRecovery CMSServlet.
 * Searches for archived keys eligible for recovery.
 *
 * The original servlet searches the key repository using an LDAP filter,
 * supports pagination via querySentinel, and injects realm-based access
 * controls into the filter.
 *
 * Legacy URL: /agent/kra/srchKeyForRecovery
 */
@Path("agent/kra/srchKeyForRecovery")
public class KRASrchKeyForRecoveryResource {

    private static final Logger logger = LoggerFactory.getLogger(KRASrchKeyForRecoveryResource.class);
    private static final int DEFAULT_MAX_RETURNS = 100;
    private static final int DEFAULT_TIME_LIMIT = 30; // seconds

    @Inject
    KRAEngineQuarkus engineQuarkus;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response srchKeyForRecovery(
            @QueryParam("queryFilter") String queryFilter,
            @QueryParam("maxCount") String maxCountStr,
            @QueryParam("maxResults") String maxResultsStr,
            @QueryParam("timeLimit") String timeLimitStr,
            @QueryParam("querySentinel") String querySentinel,
            @QueryParam("publicKeyData") String publicKeyData,
            @QueryParam("realm") String realm) {

        logger.info("KRASrchKeyForRecoveryResource: Searching keys for recovery");

        KRAEngine engine = engineQuarkus.getEngine();
        KeyRepository keyDB = engine.getKeyRepository();
        KeyRecoveryAuthority kra = engine.getKRA();

        int maxResults = -1;
        int timeLimit = DEFAULT_TIME_LIMIT;

        if (maxResultsStr != null && !maxResultsStr.isEmpty()) {
            try {
                maxResults = Integer.parseInt(maxResultsStr);
            } catch (NumberFormatException e) {
                // use default
            }
        }

        if (timeLimitStr != null && !timeLimitStr.isEmpty()) {
            try {
                int parsed = Integer.parseInt(timeLimitStr);
                if (parsed > 0 && parsed <= DEFAULT_TIME_LIMIT) {
                    timeLimit = parsed;
                }
            } catch (NumberFormatException e) {
                // use default
            }
        }

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode result = mapper.createObjectNode();
        ArrayNode keysArray = mapper.createArrayNode();

        String filter = queryFilter;
        if (filter == null || filter.isEmpty()) {
            filter = "(keyState=VALID)";
        }

        try {
            // Prevent realm injection through the query filter
            if (filter.contains("(realm=")) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity("{\"Status\":\"1\",\"Error\":\"Query filter cannot contain realm\"}")
                        .type(MediaType.APPLICATION_JSON)
                        .build();
            }

            // Inject realm-based access control into the filter
            if (realm != null && !realm.isEmpty()) {
                filter = "(&" + filter + "(realm=" + LDAPUtil.escapeFilter(realm) + "))";
            } else {
                filter = "(&" + filter + "(!(realm=*)))";
            }

            // Get archiver name for response metadata
            X500Name archiverName = kra.getX500Name();

            result.put("op", "srchKeyForRecovery");
            if (archiverName != null) {
                result.put("archiverName", archiverName.toString());
            }
            result.put("queryFilter", filter);
            if (publicKeyData != null) {
                result.put("publicKeyData", publicKeyData);
            }

            logger.debug("KRASrchKeyForRecoveryResource: Searching with filter={} timeLimit={}",
                    filter, timeLimit);

            Enumeration<KeyRecord> records = keyDB.searchKeys(filter, maxResults, timeLimit);
            int count = 0;

            if (records != null) {
                while (records.hasMoreElements()) {
                    KeyRecord keyRecord = records.nextElement();
                    if (keyRecord != null) {
                        ObjectNode keyNode = mapper.createObjectNode();
                        keyNode.put("serialNumber", keyRecord.getSerialNumber().toString());
                        keyNode.put("serialNumberInHex", keyRecord.getSerialNumber().toString(16));
                        keyNode.put("ownerName", keyRecord.getOwnerName());
                        keyNode.put("algorithm", keyRecord.getAlgorithm());
                        keyNode.put("keySize", keyRecord.getKeySize());
                        keyNode.put("state", keyRecord.getState().toString());

                        keysArray.add(keyNode);
                        count++;
                    }
                }
            }

            result.put("Status", "0");
            result.put("maxSize", DEFAULT_MAX_RETURNS);
            result.put("totalRecordCount", count);
            result.set("keys", keysArray);

        } catch (Exception e) {
            logger.error("KRASrchKeyForRecoveryResource: Error searching keys: {}", e.getMessage(), e);
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
