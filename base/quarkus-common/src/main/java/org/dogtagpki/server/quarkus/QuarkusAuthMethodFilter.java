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

import org.dogtagpki.server.rest.AuthMethodChecker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.ForbiddenException;

/**
 * Quarkus ContainerRequestFilter for authentication method checking.
 *
 * Consolidates per-servlet WebFilter AuthMethod classes into a single
 * ContainerRequestFilter per subsystem. Each subsystem extends this
 * class and registers path-to-authMethod mappings.
 */
public abstract class QuarkusAuthMethodFilter implements ContainerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(QuarkusAuthMethodFilter.class);

    private final Map<String, PathAuthMethodMapping> pathMappings = new HashMap<>();
    private AuthMethodChecker authMethodChecker;

    /**
     * Subclasses must provide the subsystem name (e.g., "ca", "kra").
     */
    protected abstract String getSubsystem();

    /**
     * Register a path prefix with an auth method name.
     * Pass null for authMethod to skip auth method checking for the path.
     */
    protected void addPathAuthMethod(String pathPrefix, String authMethod) {
        pathMappings.put(pathPrefix, new PathAuthMethodMapping(authMethod, null));
    }

    /**
     * Register a path prefix with a default auth method and method-specific overrides.
     * The authMethodMap keys are "METHOD:subpath" (e.g., "GET:installToken").
     */
    protected void addPathAuthMethod(String pathPrefix, String authMethod, Map<String, String> authMethodMap) {
        pathMappings.put(pathPrefix, new PathAuthMethodMapping(authMethod, authMethodMap));
    }

    @Override
    public void filter(ContainerRequestContext requestContext) {
        String method = requestContext.getMethod();
        String path = requestContext.getUriInfo().getPath();
        if (path.startsWith("/")) {
            path = path.substring(1);
        }

        String authMethodName = resolveAuthMethod(method, path);

        if (authMethodName == null) {
            logger.debug("QuarkusAuthMethodFilter: No auth method for {}:{} - skipping", method, path);
            return;
        }

        logger.debug("QuarkusAuthMethodFilter: Checking auth method {} for {}:{}", authMethodName, method, path);

        Principal principal = requestContext.getSecurityContext().getUserPrincipal();

        try {
            getOrCreateChecker().checkAuthenticationMethod(principal, authMethodName);
        } catch (ForbiddenException fe) {
            try {
                requestContext.abortWith(
                        Response.status(Response.Status.FORBIDDEN)
                                .type(MediaType.APPLICATION_JSON)
                                .entity(fe.getData().toJSON())
                                .build());
            } catch (Exception e) {
                logger.error("QuarkusAuthMethodFilter: Failed to serialize error response: {}", e.getMessage(), e);
                requestContext.abortWith(
                        Response.status(Response.Status.FORBIDDEN).build());
            }
        }
    }

    private String resolveAuthMethod(String method, String path) {
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

        PathAuthMethodMapping mapping = pathMappings.get(bestPrefix);

        String subpath = path.substring(bestPrefix.length());
        if (subpath.startsWith("/")) {
            subpath = subpath.substring(1);
        }

        if (mapping.authMethodMap != null && !mapping.authMethodMap.isEmpty()) {
            String searchKey = method + ":" + subpath;

            String matchedKey = mapping.authMethodMap.keySet().stream()
                    .filter(key -> {
                        String keyRegex = key.replace("{}", "([^/]+)");
                        return searchKey.matches(keyRegex);
                    })
                    .sorted(Comparator.naturalOrder())
                    .findFirst()
                    .orElse(null);

            if (matchedKey != null) {
                return mapping.authMethodMap.get(matchedKey);
            }
        }

        return mapping.defaultAuthMethod;
    }

    private synchronized AuthMethodChecker getOrCreateChecker() {
        if (authMethodChecker == null) {
            authMethodChecker = new AuthMethodChecker(getSubsystem());
        }
        return authMethodChecker;
    }

    private static class PathAuthMethodMapping {
        final String defaultAuthMethod;
        final Map<String, String> authMethodMap;

        PathAuthMethodMapping(String defaultAuthMethod, Map<String, String> authMethodMap) {
            this.defaultAuthMethod = defaultAuthMethod;
            this.authMethodMap = authMethodMap;
        }
    }
}
