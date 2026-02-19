//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.quarkus;

import java.io.InputStream;
import java.io.OutputStream;

import jakarta.inject.Inject;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.StreamingOutput;

import org.dogtagpki.server.tps.TPSSession;
import org.dogtagpki.tps.TPSConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.smallrye.common.annotation.Blocking;
import io.vertx.core.http.HttpServerRequest;

/**
 * JAX-RS resource replacing the legacy TPSServlet.
 * Handles TPS secure channel for token operations.
 *
 * The TPS protocol uses a bidirectional streaming conversation over HTTP:
 * the client sends chunked POST data and the server reads/writes multiple
 * TPS messages during a single request via TPSConnection and TPSSession.
 *
 * This resource runs on a worker thread (@Blocking) because TPSSession.process()
 * performs synchronous blocking I/O over the TPSConnection streams.
 *
 * Legacy URL: /tps
 */
@Path("tps")
public class TPSSecureChannelResource {

    private static final Logger logger = LoggerFactory.getLogger(TPSSecureChannelResource.class);

    @Inject
    TPSEngineQuarkus engineQuarkus;

    @POST
    @Blocking
    public Response processTokenOperation(
            InputStream requestBody,
            @Context HttpHeaders headers,
            @Context HttpServerRequest vertxRequest) {

        String encoding = headers.getHeaderString("Transfer-Encoding");

        logger.debug("TPSSecureChannelResource: Encoding: {}", encoding);
        logger.debug("TPSSecureChannelResource: Method: POST");

        if (!"chunked".equals(encoding)) {
            logger.warn("Returning 400 Bad Request - Transfer-Encoding is not chunked");
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        String ipAddress = vertxRequest.remoteAddress() != null
                ? vertxRequest.remoteAddress().host()
                : null;

        logger.debug("TPSSecureChannelResource: Remote address: {}", ipAddress);

        StreamingOutput streamingOutput = (OutputStream outputStream) -> {
            // Set chunked transfer encoding on the response by flushing
            // before writing message data. The underlying Vert.x HTTP
            // server handles chunked encoding automatically.
            outputStream.flush();

            TPSConnection con = new TPSConnection(requestBody, outputStream, true);
            logger.debug("TPSConnection created: {}", con);

            TPSSession session = new TPSSession(con, ipAddress);
            logger.debug("TPSSession created: {}", session);

            session.process();

            logger.debug("After session.process() exiting ...");
        };

        return Response.ok(streamingOutput)
                .header("Transfer-Encoding", "chunked")
                .build();
    }
}
