//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.quarkus;

import java.util.Collection;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestRecord;
import com.netscape.cmscore.request.RequestRepository;

/**
 * Base JAX-RS resource replacing the legacy QueryReq CMSServlet.
 * Shows paged list of requests matching search criteria.
 */
public abstract class QueryReqResourceBase {

    private static final Logger logger = LoggerFactory.getLogger(QueryReqResourceBase.class);
    private static final int DEFAULT_MAX_RESULTS = 100;

    protected abstract CMSEngine getEngine();

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response queryRequests(
            @QueryParam("filter") String filter,
            @QueryParam("maxCount") String maxCountStr,
            @QueryParam("reqStatus") String reqStatus) {

        logger.info("QueryReqResourceBase: Querying requests");

        CMSEngine engine = getEngine();
        RequestRepository requestRepository = engine.getRequestRepository();

        int maxCount = DEFAULT_MAX_RESULTS;
        if (maxCountStr != null) {
            try {
                maxCount = Integer.parseInt(maxCountStr);
            } catch (NumberFormatException e) {
                // use default
            }
        }

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode result = mapper.createObjectNode();
        ArrayNode requestsArray = mapper.createArrayNode();

        // Build filter if reqStatus is provided and filter is empty
        if ((filter == null || filter.isEmpty()) && reqStatus != null && !reqStatus.isEmpty()) {
            filter = "(requeststate=" + reqStatus + ")";
        }

        if (filter == null || filter.isEmpty()) {
            filter = "(requeststate=*)";
        }

        try {
            Collection<RequestRecord> records = requestRepository.listRequestsByFilter(filter, maxCount);
            int count = 0;

            for (RequestRecord record : records) {
                Request request = record.toRequest();

                ObjectNode reqNode = mapper.createObjectNode();
                reqNode.put("requestId", request.getRequestId().toString());
                reqNode.put("requestType", request.getRequestType());
                reqNode.put("requestStatus", request.getRequestStatus().toString());
                reqNode.put("createdOn", request.getCreationTime().getTime() / 1000);
                reqNode.put("modifiedOn", request.getModificationTime().getTime() / 1000);

                requestsArray.add(reqNode);
                count++;
            }

            result.put("Status", "0");
            result.put("totalCount", count);
            result.set("requests", requestsArray);

        } catch (Exception e) {
            logger.error("QueryReqResourceBase: Error: {}", e.getMessage(), e);
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
