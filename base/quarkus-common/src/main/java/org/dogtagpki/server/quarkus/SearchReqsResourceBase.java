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
import com.netscape.cmscore.request.RequestRecord;
import com.netscape.cmscore.request.RequestRepository;

/**
 * Base JAX-RS resource replacing the legacy SearchReqs CMSServlet.
 * Searches for requests matching a complex query filter.
 */
public abstract class SearchReqsResourceBase {

    private static final Logger logger = LoggerFactory.getLogger(SearchReqsResourceBase.class);
    private static final int DEFAULT_MAX_RESULTS = 100;

    protected abstract CMSEngine getEngine();

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response searchRequests(
            @QueryParam("filter") String filter,
            @QueryParam("maxResults") String maxResultsStr) {

        logger.info("SearchReqsResourceBase: Searching requests");

        CMSEngine engine = getEngine();
        RequestRepository requestRepository = engine.getRequestRepository();

        int maxResults = DEFAULT_MAX_RESULTS;
        if (maxResultsStr != null) {
            try {
                maxResults = Integer.parseInt(maxResultsStr);
            } catch (NumberFormatException e) {
                // use default
            }
        }

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode result = mapper.createObjectNode();
        ArrayNode requestsArray = mapper.createArrayNode();

        if (filter == null || filter.isEmpty()) {
            result.put("Status", "1");
            result.put("Error", "Missing filter parameter");
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(result.toString())
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        try {
            Collection<RequestRecord> records = requestRepository.listRequestsByFilter(filter, maxResults);
            int count = 0;

            for (RequestRecord record : records) {
                ObjectNode reqNode = mapper.createObjectNode();
                reqNode.put("requestId", record.getRequestId().toString());

                // Use get() to access RequestRecord fields
                String requestType = (String) record.get(RequestRecord.ATTR_REQUEST_TYPE);
                if (requestType != null) {
                    reqNode.put("requestType", requestType);
                }

                Object requestState = record.get(RequestRecord.ATTR_REQUEST_STATE);
                if (requestState != null) {
                    reqNode.put("requestStatus", requestState.toString());
                }

                java.util.Date createTime = (java.util.Date) record.get(RequestRecord.ATTR_CREATE_TIME);
                if (createTime != null) {
                    reqNode.put("createdOn", createTime.getTime() / 1000);
                }

                java.util.Date modifyTime = (java.util.Date) record.get(RequestRecord.ATTR_MODIFY_TIME);
                if (modifyTime != null) {
                    reqNode.put("modifiedOn", modifyTime.getTime() / 1000);
                }

                requestsArray.add(reqNode);
                count++;
            }

            result.put("Status", "0");
            result.put("totalCount", count);
            result.set("requests", requestsArray);

        } catch (Exception e) {
            logger.error("SearchReqsResourceBase: Error: {}", e.getMessage(), e);
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
