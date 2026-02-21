//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.security.Principal;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;

import org.dogtagpki.server.rest.base.AccountServletBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.account.Account;

@Path("v2/account")
public class CAAccountResource {

    private static final Logger logger = LoggerFactory.getLogger(CAAccountResource.class);

    @Context
    SecurityContext securityContext;

    @GET
    @Path("login")
    @Produces(MediaType.APPLICATION_JSON)
    public Response login() throws Exception {
        Principal principal = securityContext.getUserPrincipal();
        logger.debug("CAAccountResource.login(): principal={}", principal != null ? principal.getName() : "null");
        if (principal == null) {
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }
        Account account = AccountServletBase.createAccount(principal);
        return Response.ok(account.toJSON()).build();
    }

    @GET
    @Path("logout")
    public Response logout() {
        logger.debug("CAAccountResource.logout()");
        return Response.noContent().build();
    }
}
