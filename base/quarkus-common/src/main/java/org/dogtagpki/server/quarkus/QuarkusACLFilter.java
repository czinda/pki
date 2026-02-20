//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.quarkus;

import java.security.Principal;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.rest.ACLChecker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.cmscore.apps.CMSEngine;

/**
 * Quarkus ContainerRequestFilter for ACL checking.
 *
 * Consolidates per-servlet WebFilter ACL classes into a single
 * ContainerRequestFilter per subsystem. Each subsystem extends
 * this class and registers path-to-ACL mappings.
 *
 * Path mappings use a prefix-based approach:
 * - Register a path prefix (e.g., "v2/audit") with a default ACL
 *   and optional method:subpath-specific ACL overrides.
 * - Unregistered paths or null ACL names are unprotected.
 */
public abstract class QuarkusACLFilter implements ContainerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(QuarkusACLFilter.class);

    private final Map<String, PathAclMapping> pathMappings = new HashMap<>();
    private ACLChecker aclChecker;

    /**
     * Subclasses must provide the CMSEngine for ACL evaluation.
     */
    protected abstract CMSEngine getEngine();

    /**
     * Subclasses must provide the subsystem name (e.g., "ca", "kra").
     */
    protected abstract String getSubsystem();

    /**
     * Register a path prefix with a default ACL name.
     * Paths matching this prefix will use the given ACL.
     * Pass null for defaultAcl to mark the path as unprotected.
     */
    protected void addPathAcl(String pathPrefix, String defaultAcl) {
        pathMappings.put(pathPrefix, new PathAclMapping(defaultAcl, null));
    }

    /**
     * Register a path prefix with a default ACL and method-specific overrides.
     * The aclMap keys are "METHOD:subpath" (e.g., "GET:", "PATCH:", "GET:files/{}").
     */
    protected void addPathAcl(String pathPrefix, String defaultAcl, Map<String, String> aclMap) {
        pathMappings.put(pathPrefix, new PathAclMapping(defaultAcl, aclMap));
    }

    @Override
    public void filter(ContainerRequestContext requestContext) {
        String method = requestContext.getMethod();
        String path = requestContext.getUriInfo().getPath();
        // Strip leading slash if present
        if (path.startsWith("/")) {
            path = path.substring(1);
        }

        String aclName = resolveAcl(method, path);

        if (aclName == null) {
            logger.debug("QuarkusACLFilter: No ACL for {}:{} - unprotected", method, path);
            return;
        }

        logger.debug("QuarkusACLFilter: Checking ACL {} for {}:{}", aclName, method, path);

        Principal principal = requestContext.getSecurityContext().getUserPrincipal();

        try {
            getOrCreateChecker().checkACL(principal, method, path, aclName);
        } catch (ForbiddenException fe) {
            try {
                requestContext.abortWith(
                        Response.status(Response.Status.FORBIDDEN)
                                .type(MediaType.APPLICATION_JSON)
                                .entity(fe.getData().toJSON())
                                .build());
            } catch (Exception e) {
                logger.error("QuarkusACLFilter: Failed to serialize error response: {}", e.getMessage(), e);
                requestContext.abortWith(
                        Response.status(Response.Status.FORBIDDEN).build());
            }
        }
    }

    /**
     * Resolve the ACL name for the given HTTP method and full path.
     * Returns null if no ACL applies (unprotected).
     */
    private String resolveAcl(String method, String path) {
        // Find the longest matching path prefix
        String bestPrefix = null;
        for (String prefix : pathMappings.keySet()) {
            if (path.equals(prefix) || path.startsWith(prefix + "/")) {
                if (bestPrefix == null || prefix.length() > bestPrefix.length()) {
                    bestPrefix = prefix;
                }
            }
        }

        if (bestPrefix == null) {
            return null;
        }

        PathAclMapping mapping = pathMappings.get(bestPrefix);

        // Extract sub-path relative to the prefix
        String subpath = path.substring(bestPrefix.length());
        if (subpath.startsWith("/")) {
            subpath = subpath.substring(1);
        }

        // Try method-specific ACL map if available
        if (mapping.aclMap != null && !mapping.aclMap.isEmpty()) {
            String searchKey = method + ":" + subpath;

            // Find matching key using regex (for {} path params)
            String matchedKey = mapping.aclMap.keySet().stream()
                    .filter(key -> {
                        String keyRegex = key.replace("{}", "([^/]+)");
                        return searchKey.matches(keyRegex);
                    })
                    .sorted(Comparator.reverseOrder())
                    .findFirst()
                    .orElse(null);

            if (matchedKey != null) {
                return mapping.aclMap.get(matchedKey);
            }
        }

        return mapping.defaultAcl;
    }

    private synchronized ACLChecker getOrCreateChecker() {
        if (aclChecker == null) {
            aclChecker = new ACLChecker(getEngine(), getSubsystem());
        }
        return aclChecker;
    }

    private static class PathAclMapping {
        final String defaultAcl;
        final Map<String, String> aclMap;

        PathAclMapping(String defaultAcl, Map<String, String> aclMap) {
            this.defaultAcl = defaultAcl;
            this.aclMap = aclMap;
        }
    }
}
