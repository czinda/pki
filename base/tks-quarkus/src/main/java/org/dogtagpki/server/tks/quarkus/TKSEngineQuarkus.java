//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tks.quarkus;

import java.util.List;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;

import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.quarkus.QuarkusSocketListenerRegistry;
import org.dogtagpki.server.tks.TKSEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cms.realm.PKIPrincipalCore;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.QuarkusInstanceConfig;
import com.netscape.cmscore.usrgrp.User;

import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.StartupEvent;
import io.quarkus.security.identity.SecurityIdentity;

/**
 * CDI-managed wrapper for TKSEngine in Quarkus deployments.
 *
 * TKS extends CMSEngine and needs the full PKI infrastructure
 * (LDAP, auth, authz, etc.). This wrapper manages the real
 * TKSEngine lifecycle via CDI events and uses Quarkus
 * lifecycle management.
 */
@ApplicationScoped
public class TKSEngineQuarkus {

    private static final Logger logger = LoggerFactory.getLogger(TKSEngineQuarkus.class);

    private static TKSEngineQuarkus INSTANCE;

    private TKSEngine engine;

    public static TKSEngineQuarkus getInstance() {
        return INSTANCE;
    }

    public TKSEngine getEngine() {
        return engine;
    }

    void onStart(@Observes StartupEvent event) {
        INSTANCE = this;
        try {
            start();
        } catch (Throwable e) {
            logger.error("Failed to start TKS engine", e);
            throw new RuntimeException("TKS engine startup failed", e);
        }
    }

    void onStop(@Observes ShutdownEvent event) {
        try {
            stop();
        } catch (Throwable e) {
            logger.error("Error stopping TKS engine", e);
        }
    }

    public void start() throws Exception {
        logger.info("TKSEngineQuarkus: Starting TKS engine");

        // Configure instance directory for Quarkus
        // (sets pki.instance.dir for instance discovery)
        CMS.setInstanceConfig(new QuarkusInstanceConfig());

        // Create the real TKS engine
        engine = new TKSEngine();

        // Set Quarkus socket listener registry
        // (uses direct JSS initialization)
        engine.setSocketListenerRegistry(new QuarkusSocketListenerRegistry());

        // Start the engine (loads CS.cfg, initializes all subsystems)
        engine.start();

        logger.info("TKSEngineQuarkus: TKS engine started successfully");
    }

    public void stop() throws Exception {
        logger.info("TKSEngineQuarkus: Stopping TKS engine");

        if (engine != null) {
            engine.shutdown();
            engine = null;
        }

        logger.info("TKSEngineQuarkus: TKS engine stopped");
    }

    /**
     * Convert a Quarkus SecurityIdentity to a PKIPrincipalCore for use
     * with TKS processors that require PKI principal types.
     *
     * The TPSConnectorProcessor uses Principal for user validation
     * in shared secret operations. This method bridges the Quarkus
     * security model to the expected PKIPrincipalCore.
     *
     * @param identity the Quarkus SecurityIdentity
     * @return a PKIPrincipalCore wrapping the identity information
     */
    public static PKIPrincipalCore toPKIPrincipalCore(SecurityIdentity identity) {
        PKIPrincipalCore core = identity.getAttribute("pki.principal");
        if (core != null) {
            return core;
        }

        // Fallback: create from basic principal
        String name = identity.getPrincipal().getName();
        User user = new User();
        user.setUserID(name);
        user.setFullName(name);
        return new PKIPrincipalCore(name, null, List.of(), user, null);
    }
}
