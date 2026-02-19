//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tks.quarkus;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.ext.Provider;

import org.dogtagpki.server.quarkus.QuarkusAuthMethodFilter;

/**
 * Consolidated AuthMethod filter for TKS subsystem.
 * Replaces all individual TKS WebFilter AuthMethod classes.
 */
@Provider
@Priority(Priorities.AUTHENTICATION + 1)
public class TKSAuthMethodFilter extends QuarkusAuthMethodFilter {

    @PostConstruct
    void init() {
        addPathAuthMethod("v2/account", "account");
        addPathAuthMethod("v2/audit", "audit");
        addPathAuthMethod("v2/admin/groups", "groups");
        addPathAuthMethod("v2/admin/users", "users");
        addPathAuthMethod("v2/selftests", "selftests.read");
        addPathAuthMethod("v2/admin/tps-connectors", "tpsconnectors");

        // Unprotected
        addPathAuthMethod("v2/jobs", null);
    }

    @Override
    protected String getSubsystem() {
        return "tks";
    }
}
