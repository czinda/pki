//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.quarkus;

import java.util.Date;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.cmscore.apps.CMSEngine;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * JAX-RS resource replacing the legacy SystemInfoServlet.
 * Provides JVM diagnostics: memory, threads, garbage collection.
 */
public abstract class SystemInfoResourceBase {

    private static final Logger logger = LoggerFactory.getLogger(SystemInfoResourceBase.class);

    protected abstract CMSEngine getEngine();

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getSystemInfo(@QueryParam("op") String op) {

        ObjectMapper mapper = new ObjectMapper();

        if (op == null || op.isEmpty()) {
            // Return available operations
            ObjectNode result = mapper.createObjectNode();
            result.put("Status", "0");
            ArrayNode operations = mapper.createArrayNode();
            operations.add("general");
            operations.add("thread");
            operations.add("gc");
            result.set("operations", operations);
            return Response.ok(result.toString(), MediaType.APPLICATION_JSON).build();
        }

        switch (op) {
            case "general":
                return getGeneral(mapper);
            case "thread":
                return getThreads(mapper);
            case "gc":
                return triggerGC(mapper);
            default:
                ObjectNode error = mapper.createObjectNode();
                error.put("Status", "1");
                error.put("Error", "Unknown operation: " + op);
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(error.toString())
                        .type(MediaType.APPLICATION_JSON)
                        .build();
        }
    }

    private Response getGeneral(ObjectMapper mapper) {
        CMSEngine engine = getEngine();

        ObjectNode result = mapper.createObjectNode();
        result.put("Status", "0");
        result.put("serverStartedTime", new Date(engine.getStartupTime()).toString());
        result.put("currentTime", new Date().toString());
        result.put("availableProcessors", Runtime.getRuntime().availableProcessors());
        result.put("activeThreads", Thread.activeCount());
        result.put("maxMemory", Runtime.getRuntime().maxMemory());
        result.put("totalMemory", Runtime.getRuntime().totalMemory());
        result.put("freeMemory", Runtime.getRuntime().freeMemory());
        long totalMem = Runtime.getRuntime().totalMemory();
        long freeMem = Runtime.getRuntime().freeMemory();
        result.put("freeMemoryPercent", totalMem > 0 ? (freeMem * 100) / totalMem + "%" : "N/A");

        return Response.ok(result.toString(), MediaType.APPLICATION_JSON).build();
    }

    private Response getThreads(ObjectMapper mapper) {
        ObjectNode result = mapper.createObjectNode();
        result.put("Status", "0");

        int active = Thread.activeCount();
        Thread[] threads = new Thread[active];
        int count = Thread.enumerate(threads);

        ArrayNode threadArray = mapper.createArrayNode();
        for (int i = 0; i < count; i++) {
            ObjectNode threadNode = mapper.createObjectNode();
            threadNode.put("index", i);
            threadNode.put("name", threads[i].getName());
            threadNode.put("priority", threads[i].getPriority());
            threadNode.put("isDaemon", threads[i].isDaemon());
            threadArray.add(threadNode);
        }
        result.set("threads", threadArray);
        result.put("totalThreads", count);

        return Response.ok(result.toString(), MediaType.APPLICATION_JSON).build();
    }

    private Response triggerGC(ObjectMapper mapper) {
        Runtime.getRuntime().gc();
        Runtime.getRuntime().runFinalization();

        ObjectNode result = mapper.createObjectNode();
        result.put("Status", "0");
        result.put("message", "Garbage collection has been triggered");
        result.put("freeMemory", Runtime.getRuntime().freeMemory());
        result.put("totalMemory", Runtime.getRuntime().totalMemory());

        return Response.ok(result.toString(), MediaType.APPLICATION_JSON).build();
    }
}
