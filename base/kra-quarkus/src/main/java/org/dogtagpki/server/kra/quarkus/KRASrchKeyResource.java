//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

import java.util.Date;
import java.util.Enumeration;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.kra.KRAEngine;
import org.mozilla.jss.netscape.security.util.PrettyPrintFormat;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.MetaInfo;
import com.netscape.cmscore.dbs.KeyRecord;
import com.netscape.cmscore.dbs.KeyRepository;
import com.netscape.cmsutil.ldap.LDAPUtil;
import com.netscape.kra.KeyRecoveryAuthority;

/**
 * JAX-RS resource replacing the legacy SrchKey CMSServlet.
 * Searches for archived keys matching a query filter.
 *
 * Legacy URL: /agent/kra/srchKey
 */
@Path("agent/kra/srchKey")
public class KRASrchKeyResource {

    private static final Logger logger = LoggerFactory.getLogger(KRASrchKeyResource.class);

    private static final int DEFAULT_MAX_RETURNS = 100;
    private static final int DEFAULT_TIME_LIMIT = 30;

    @Inject
    KRAEngineQuarkus engineQuarkus;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response searchKeysGet(
            @QueryParam("queryFilter") String queryFilter,
            @QueryParam("maxResults") @DefaultValue("-1") int maxResults,
            @QueryParam("timeLimit") @DefaultValue("-1") int timeLimit,
            @QueryParam("realm") String realm) {

        return doSearchKeys(queryFilter, maxResults, timeLimit, realm);
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response searchKeysPost(
            @QueryParam("queryFilter") String queryFilter,
            @QueryParam("maxResults") @DefaultValue("-1") int maxResults,
            @QueryParam("timeLimit") @DefaultValue("-1") int timeLimit,
            @QueryParam("realm") String realm) {

        return doSearchKeys(queryFilter, maxResults, timeLimit, realm);
    }

    private Response doSearchKeys(String queryFilter, int maxResults, int timeLimit, String realm) {

        logger.debug("KRASrchKeyResource.searchKeys() filter={}", queryFilter);

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode result = mapper.createObjectNode();

        try {
            if (queryFilter == null || queryFilter.trim().isEmpty()) {
                result.put("error", "Missing required parameter: queryFilter");
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(result.toString())
                        .build();
            }

            if (queryFilter.contains("(realm=")) {
                result.put("error", "Query filter cannot contain realm");
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(result.toString())
                        .build();
            }

            KRAEngine engine = engineQuarkus.getEngine();
            KeyRepository keyDB = engine.getKeyRepository();
            KeyRecoveryAuthority kra = engine.getKRA();
            X500Name authName = kra.getX500Name();

            // Apply realm filter
            String filter;
            if (realm != null && !realm.trim().isEmpty()) {
                filter = "(&" + queryFilter + "(realm=" + LDAPUtil.escapeFilter(realm) + "))";
            } else {
                filter = "(&" + queryFilter + "(!(realm=*)))";
            }

            // Enforce time limit
            int effectiveTimeLimit = timeLimit;
            if (effectiveTimeLimit == -1 || effectiveTimeLimit > DEFAULT_TIME_LIMIT) {
                logger.debug("KRASrchKeyResource: Resetting timelimit from {} to {}", effectiveTimeLimit, DEFAULT_TIME_LIMIT);
                effectiveTimeLimit = DEFAULT_TIME_LIMIT;
            }

            logger.debug("KRASrchKeyResource: Start searching ... timelimit={}", effectiveTimeLimit);
            Enumeration<KeyRecord> e = keyDB.searchKeys(filter, maxResults, effectiveTimeLimit);

            result.put("archiverName", authName != null ? authName.toString() : "");
            result.put("queryFilter", filter);

            ArrayNode records = mapper.createArrayNode();
            int count = 0;

            if (e != null) {
                while (e.hasMoreElements()) {
                    KeyRecord rec = e.nextElement();
                    if (rec != null) {
                        ObjectNode recNode = mapper.createObjectNode();
                        fillKeyRecordInfo(rec, recNode);
                        records.add(recNode);
                        count++;
                    }
                }
            }

            result.set("records", records);
            result.put("totalRecordCount", count);
            result.put("maxSize", DEFAULT_MAX_RETURNS);

            return Response.ok(result.toString(), MediaType.APPLICATION_JSON).build();

        } catch (EBaseException e) {
            logger.error("KRASrchKeyResource: Search failed: {}", e.getMessage(), e);
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
