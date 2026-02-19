//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.quarkus;

import java.util.Map;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.ext.Provider;

import org.dogtagpki.server.quarkus.QuarkusACLFilter;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * Consolidated ACL filter for TPS subsystem.
 * Replaces all individual TPS WebFilter ACL classes.
 */
@Provider
@Priority(Priorities.AUTHORIZATION)
public class TPSAclFilter extends QuarkusACLFilter {

    @Inject
    TPSEngineQuarkus engineQuarkus;

    @PostConstruct
    void init() {
        addPathAcl("v2/account", "account.login", Map.of(
                "GET:login", "account.login",
                "GET:logout", "account.logout"));

        addPathAcl("v2/audit", "audit.read", Map.of(
                "GET:", "audit.read",
                "PATCH:", "audit.modify",
                "POST:", "audit.modify",
                "GET:files", "audit-log.read",
                "GET:files/{}", "audit-log.read"));

        addPathAcl("v2/admin/groups", "groups");
        addPathAcl("v2/admin/users", "users");

        addPathAcl("v2/selftests", "selftests.read", Map.of(
                "POST:", "selftests.execute",
                "POST:run", "selftests.execute",
                "POST:{}/run", "selftests.execute"));

        addPathAcl("v2/securityDomain", null, Map.of(
                "GET:installToken", "securityDomain.read",
                "PUT:hosts", "securityDomain.modify",
                "DELETE:hosts/{}", "securityDomain.modify"));

        // Authenticators
        addPathAcl("v2/authenticators", "authenticators.read", Map.of(
                "POST:", "authenticators.add",
                "PATCH:{}", "authenticators.modify",
                "POST:{}", "authenticators.change-status",
                "DELETE:{}", "authenticators.remove"));

        // Config
        addPathAcl("v2/config", "config.read", Map.of(
                "PATCH:", "config.modify"));

        // Connectors
        addPathAcl("v2/connectors", "connectors.read", Map.of(
                "POST:", "connectors.add",
                "PATCH:{}", "connectors.modify",
                "POST:{}", "connectors.change-status",
                "DELETE:{}", "connectors.remove"));

        // Profile Mappings
        addPathAcl("v2/profile-mappings", "profile-mappings.read", Map.of(
                "POST:", "profile-mappings.add",
                "PATCH:{}", "profile-mappings.modify",
                "POST:{}", "profiles-mappings.change-status",
                "DELETE:{}", "profile-mappings.remove"));

        // Profiles
        addPathAcl("v2/profiles", "profiles.read", Map.of(
                "POST:", "profiles.add",
                "PATCH:{}", "profiles.modify",
                "POST:{}", "profiles.change-status",
                "DELETE:{}", "profiles.remove"));

        // Tokens
        addPathAcl("v2/tokens", "tokens.read", Map.of(
                "POST:", "tokens.add",
                "PUT:{}", "tokens.modify",
                "PATCH:{}", "tokens.modify",
                "POST:{}", "tokens.modify",
                "DELETE:{}", "tokens.remove"));

        // Unprotected
        addPathAcl("v2/activities", null);
        addPathAcl("v2/jobs", null);
        addPathAcl("v2/certs", null);
    }

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }

    @Override
    protected String getSubsystem() {
        return "tps";
    }
}
