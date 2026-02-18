//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

import java.io.File;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PATCH;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;

import org.dogtagpki.server.rest.base.AuditServletBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.logging.AuditConfig;
import com.netscape.certsrv.logging.AuditFileCollection;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * JAX-RS resource for KRA audit operations.
 * Replaces KRAAuditServlet.
 */
@Path("v2/audit")
public class KRAAuditResource {

    private static final Logger logger = LoggerFactory.getLogger(KRAAuditResource.class);

    @Inject
    KRAEngineQuarkus engineQuarkus;

    @Context
    SecurityContext securityContext;

    private AuditServletBase createBase() {
        return new AuditServletBase(engineQuarkus.getEngine());
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAuditConfig() throws Exception {
        logger.debug("KRAAuditResource.getAuditConfig()");
        AuditConfig config = createBase().createAuditConfig();
        return Response.ok(config.toJSON()).build();
    }

    @PATCH
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response updateAuditConfig(String requestData) throws Exception {
        logger.debug("KRAAuditResource.updateAuditConfig()");
        AuditConfig auditConfig = JSONSerializer.fromJSON(requestData, AuditConfig.class);
        String principalName = securityContext.getUserPrincipal().getName();
        AuditConfig updated = createBase().updateAuditConfig(auditConfig, principalName);
        return Response.ok(updated.toJSON()).build();
    }

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response changeAuditStatus(@QueryParam("action") String action) throws Exception {
        logger.debug("KRAAuditResource.changeAuditStatus(): action={}", action);
        String principalName = securityContext.getUserPrincipal().getName();
        AuditConfig config = createBase().changeAuditStatus(action, principalName);
        return Response.ok(config.toJSON()).build();
    }

    @GET
    @Path("files")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAuditFiles() throws Exception {
        logger.debug("KRAAuditResource.getAuditFiles()");
        AuditFileCollection files = createBase().findAuditFiles();
        return Response.ok(files.toJSON()).build();
    }

    @GET
    @Path("files/{filename}")
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    public Response getAuditFile(@PathParam("filename") String filename) throws Exception {
        logger.debug("KRAAuditResource.getAuditFile(): filename={}", filename);
        File auditFile = createBase().getAuditFile(filename);
        return Response.ok(auditFile)
                .type(MediaType.APPLICATION_OCTET_STREAM)
                .header("Content-Disposition", "attachment; filename=\"" + auditFile.getName() + "\"")
                .build();
    }
}
