//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.quarkus;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.security.Principal;
import java.util.Locale;
import java.util.ResourceBundle;

import jakarta.inject.Inject;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.SecurityContext;

import org.dogtagpki.server.authentication.AuthToken;

import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.cms.realm.PKIPrincipalCore;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;

import io.quarkus.security.identity.SecurityIdentity;
import io.vertx.ext.web.RoutingContext;

/**
 * Base JAX-RS resource class for Quarkus PKI endpoints.
 *
 * Replaces PKIServlet for Quarkus deployments, providing:
 * - SecurityIdentity injection for authentication
 * - SessionContext setup for downstream business logic
 * - Resource bundle loading for localization
 *
 * Subsystem resources should extend this class.
 */
public abstract class PKIResource {

    public static final int DEFAULT_MAXTIME = 0;
    public static final int DEFAULT_SIZE = 20;
    public static final int MIN_FILTER_LENGTH = 3;
    public static final int DEFAULT_LONG_CACHE_LIFETIME = 1000;

    private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PKIResource.class);

    @Inject
    SecurityIdentity securityIdentity;

    @Context
    SecurityContext securityContext;

    @Context
    RoutingContext routingContext;

    /**
     * Get the CMSEngine for this subsystem.
     * Subclasses must implement this to return their engine instance.
     */
    protected abstract CMSEngine getEngine();

    /**
     * Get the subsystem name (e.g. "ca", "kra").
     */
    protected String getSubsystemName() {
        return getEngine().getID();
    }

    /**
     * Set up the ThreadLocal SessionContext for downstream business logic.
     * Call this at the beginning of resource methods that need session context.
     */
    protected void setSessionContext() {
        Principal principal = securityContext.getUserPrincipal();

        if (principal == null) {
            logger.debug("PKIResource.setSessionContext: Not authenticated.");
            SessionContext.releaseContext();
            return;
        }

        logger.debug("PKIResource.setSessionContext: principal: {}", principal.getName());

        AuthToken authToken = null;

        // Extract PKIPrincipalCore from SecurityIdentity attributes
        PKIPrincipalCore pkiPrincipal = securityIdentity.getAttribute("pki.principal");
        if (pkiPrincipal != null) {
            authToken = (AuthToken) pkiPrincipal.getAuthToken();
        }

        // If missing auth token but AuthSubsystem enabled, reject request.
        if (authToken == null && getEngine().getAuthSubsystem() != null) {
            logger.warn("PKIResource.setSessionContext: No authorization token present.");
            throw new ForbiddenException("No authorization token present.");
        }

        SessionContext context = SessionContext.getContext();

        String ip = routingContext.request().remoteAddress().host();
        context.put(SessionContext.IPADDRESS, ip);

        String acceptLanguage = routingContext.request().getHeader("Accept-Language");
        Locale locale = acceptLanguage != null ? Locale.forLanguageTag(acceptLanguage) : Locale.getDefault();
        context.put(SessionContext.LOCALE, locale);

        if (authToken != null)
            context.put(SessionContext.AUTH_TOKEN, authToken);
        context.put(SessionContext.USER_ID, principal.getName());

        if (pkiPrincipal != null && pkiPrincipal.getUser() != null)
            context.put(SessionContext.USER, pkiPrincipal.getUser());
    }

    protected String getSubsystemConfDir() {
        return CMS.getInstanceDir() + File.separator + getSubsystemName() + File.separator + "conf";
    }

    protected String getSharedSubsystemConfDir() {
        return File.separator + "usr" + File.separator + "share" + File.separator + "pki" +
                File.separator + getSubsystemName() + File.separator + "conf";
    }

    protected ResourceBundle getResourceBundle(String name, Locale locale) throws MalformedURLException {
        URL[] urls = {
                new File(getSubsystemConfDir()).toURI().toURL(),
                new File(getSharedSubsystemConfDir()).toURI().toURL()
        };
        ClassLoader loader = new URLClassLoader(urls);
        return ResourceBundle.getBundle(name, locale, loader);
    }
}
