//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.util.Map;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.ext.Provider;

import org.dogtagpki.server.quarkus.QuarkusACLFilter;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * Consolidated ACL filter for CA subsystem.
 * Replaces all individual CA WebFilter ACL classes.
 */
@Provider
@Priority(Priorities.AUTHORIZATION)
public class CAAclFilter extends QuarkusACLFilter {

    @Inject
    CAEngineQuarkus engineQuarkus;

    @PostConstruct
    void init() {
        // Account
        addPathAcl("v2/account", "account.login", Map.of(
                "GET:login", "account.login",
                "GET:logout", "account.logout"));

        // Audit
        addPathAcl("v2/audit", "audit.read", Map.of(
                "GET:", "audit.read",
                "PATCH:", "audit.modify",
                "POST:", "audit.modify",
                "GET:files", "audit-log.read",
                "GET:files/{}", "audit-log.read"));

        // Groups
        addPathAcl("v2/admin/groups", "groups");

        // Users
        addPathAcl("v2/admin/users", "users");

        // Self Tests
        addPathAcl("v2/selftests", "selftests.read", Map.of(
                "POST:", "selftests.execute",
                "POST:run", "selftests.execute",
                "POST:{}/run", "selftests.execute"));

        // Security Domain
        addPathAcl("v2/securityDomain", null, Map.of(
                "GET:installToken", "securityDomain.read",
                "PUT:hosts", "securityDomain.modify",
                "DELETE:hosts/{}", "securityDomain.modify"));

        // Agent Certs
        addPathAcl("v2/agent/certs", "certs");

        // Agent Cert Requests
        addPathAcl("v2/agent/certrequests", "certrequests");

        // Authorities
        addPathAcl("v2/authorities", null, Map.of(
                "POST:", "authorities.create",
                "PUT:{}", "authorities.modify",
                "DELETE:{}", "authorities.delete",
                "POST:{}/enable", "authorities.modify",
                "POST:{}/disable", "authorities.modify",
                "POST:{}/renew", "authorities.modify"));

        // KRA Connector
        addPathAcl("v2/admin/kraconnector", "kraconnectors");

        // Profiles
        addPathAcl("v2/profiles", null, Map.of(
                "GET:", "profiles.list",
                "GET:{}", "profiles.read",
                "GET:{}/raw", "profiles.read",
                "POST:", "profiles.create",
                "POST:raw", "profiles.create",
                "POST:{}", "profiles.approve",
                "PUT:{}", "profiles.modify",
                "PUT:{}/raw", "profiles.modify",
                "DELETE:{}", "profiles.delete"));

        // Dashboard
        addPathAcl("v2/dashboard", "dashboard");

        // Unprotected paths (null ACL)
        addPathAcl("v2/info", null);
        addPathAcl("v2/certs", null);
        addPathAcl("v2/certrequests", null);
        addPathAcl("v2/jobs", null);
        addPathAcl("v2/config/features", null);
        addPathAcl("v2/config/cert", null);
        addPathAcl("v2/installer", null);
    }

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }

    @Override
    protected String getSubsystem() {
        return "ca";
    }
}
