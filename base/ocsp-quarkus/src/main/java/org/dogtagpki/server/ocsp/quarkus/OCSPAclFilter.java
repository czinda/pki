//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ocsp.quarkus;

import java.util.Map;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.ext.Provider;

import org.dogtagpki.server.quarkus.QuarkusACLFilter;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * Consolidated ACL filter for OCSP subsystem.
 * Replaces all individual OCSP WebFilter ACL classes.
 */
@Provider
@Priority(Priorities.AUTHORIZATION)
public class OCSPAclFilter extends QuarkusACLFilter {

    @Inject
    OCSPEngineQuarkus engineQuarkus;

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

        // Unprotected
        addPathAcl("v2/jobs", null);
    }

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }

    @Override
    protected String getSubsystem() {
        return "ocsp";
    }
}
