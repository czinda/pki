//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.quarkus;

import java.util.Map;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.ext.Provider;

import org.dogtagpki.server.quarkus.QuarkusAuthMethodFilter;

/**
 * Consolidated AuthMethod filter for TPS subsystem.
 * Replaces all individual TPS WebFilter AuthMethod classes.
 */
@Provider
@Priority(Priorities.AUTHENTICATION + 1)
public class TPSAuthMethodFilter extends QuarkusAuthMethodFilter {

    @PostConstruct
    void init() {
        addPathAuthMethod("v2/account", "account");
        addPathAuthMethod("v2/audit", "audit");
        addPathAuthMethod("v2/admin/groups", "groups");
        addPathAuthMethod("v2/admin/users", "users");
        addPathAuthMethod("v2/selftests", "selftests.read");
        addPathAuthMethod("v2/securityDomain", null, Map.of(
                "GET:installToken", "securityDomain.installToken"));
        addPathAuthMethod("v2/authenticators", "authenticators");
        addPathAuthMethod("v2/config", "config");
        addPathAuthMethod("v2/connectors", "connectors");
        addPathAuthMethod("v2/profile-mappings", "profile-mappings");
        addPathAuthMethod("v2/profiles", "profiles");
        addPathAuthMethod("v2/tokens", "tokens");

        // Unprotected
        addPathAuthMethod("v2/activities", null);
        addPathAuthMethod("v2/jobs", null);
        addPathAuthMethod("v2/certs", null);
    }

    @Override
    protected String getSubsystem() {
        return "tps";
    }
}
