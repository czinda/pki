//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.util.Map;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.ext.Provider;

import org.dogtagpki.server.quarkus.QuarkusAuthMethodFilter;

/**
 * Consolidated AuthMethod filter for CA subsystem.
 * Replaces all individual CA WebFilter AuthMethod classes.
 */
@Provider
@Priority(Priorities.AUTHENTICATION + 1)
public class CAAuthMethodFilter extends QuarkusAuthMethodFilter {

    @PostConstruct
    void init() {
        addPathAuthMethod("v2/account", "account");
        addPathAuthMethod("v2/audit", "audit");
        addPathAuthMethod("v2/admin/groups", "groups");
        addPathAuthMethod("v2/admin/users", "users");
        addPathAuthMethod("v2/selftests", "selftests.read");
        addPathAuthMethod("v2/securityDomain", null, Map.of(
                "GET:installToken", "securityDomain.installToken"));
        addPathAuthMethod("v2/agent/certs", "certs");
        addPathAuthMethod("v2/agent/certrequests", "certrequests");
        addPathAuthMethod("v2/authorities", null, Map.of(
                "POST:", "authorities",
                "PUT:{}", "authorities",
                "DELETE:{}", "authorities",
                "POST:{}/enable", "authorities",
                "POST:{}/disable", "authorities",
                "POST:{}/renew", "authorities"));
        addPathAuthMethod("v2/admin/kraconnector", "kraconnectors");
        addPathAuthMethod("v2/profiles", "profiles");
        addPathAuthMethod("v2/dashboard", null);

        // Unprotected paths
        addPathAuthMethod("v2/info", null);
        addPathAuthMethod("v2/certs", null);
        addPathAuthMethod("v2/certrequests", null);
        addPathAuthMethod("v2/jobs", null);
        addPathAuthMethod("v2/config/features", null);
        addPathAuthMethod("v2/config/cert", null);
        addPathAuthMethod("v2/installer", null);
    }

    @Override
    protected String getSubsystem() {
        return "ca";
    }
}
