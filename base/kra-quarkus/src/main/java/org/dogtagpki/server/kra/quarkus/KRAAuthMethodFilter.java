//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

import java.util.Map;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.ext.Provider;

import org.dogtagpki.server.quarkus.QuarkusAuthMethodFilter;

/**
 * Consolidated AuthMethod filter for KRA subsystem.
 * Replaces all individual KRA WebFilter AuthMethod classes.
 */
@Provider
@Priority(Priorities.AUTHENTICATION + 1)
public class KRAAuthMethodFilter extends QuarkusAuthMethodFilter {

    @PostConstruct
    void init() {
        addPathAuthMethod("v2/account", "account");
        addPathAuthMethod("v2/audit", "audit");
        addPathAuthMethod("v2/admin/groups", "groups");
        addPathAuthMethod("v2/admin/users", "users");
        addPathAuthMethod("v2/selftests", "selftests.read");
        addPathAuthMethod("v2/securityDomain", null, Map.of(
                "GET:installToken", "securityDomain.installToken"));
        addPathAuthMethod("v2/agent/keys", "keys");
        addPathAuthMethod("v2/agent/keyrequests", "keyrequests");

        // Unprotected
        addPathAuthMethod("v2/info", null);
        addPathAuthMethod("v2/jobs", null);
        addPathAuthMethod("v2/config/cert", null);
    }

    @Override
    protected String getSubsystem() {
        return "kra";
    }
}
