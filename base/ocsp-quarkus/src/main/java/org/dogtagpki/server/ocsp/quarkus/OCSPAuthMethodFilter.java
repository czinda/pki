//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ocsp.quarkus;

import java.util.Map;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.ext.Provider;

import org.dogtagpki.server.quarkus.QuarkusAuthMethodFilter;

/**
 * Consolidated AuthMethod filter for OCSP subsystem.
 * Replaces all individual OCSP WebFilter AuthMethod classes.
 */
@Provider
@Priority(Priorities.AUTHENTICATION + 1)
public class OCSPAuthMethodFilter extends QuarkusAuthMethodFilter {

    @PostConstruct
    void init() {
        addPathAuthMethod("v2/account", "account");
        addPathAuthMethod("v2/audit", "audit");
        addPathAuthMethod("v2/admin/groups", "groups");
        addPathAuthMethod("v2/admin/users", "users");
        addPathAuthMethod("v2/selftests", "selftests.read");
        addPathAuthMethod("v2/securityDomain", null, Map.of(
                "GET:installToken", "securityDomain.installToken"));

        // Unprotected
        addPathAuthMethod("v2/jobs", null);
    }

    @Override
    protected String getSubsystem() {
        return "ocsp";
    }
}
