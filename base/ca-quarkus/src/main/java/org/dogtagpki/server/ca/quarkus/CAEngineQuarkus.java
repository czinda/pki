//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.util.List;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.quarkus.QuarkusSocketListenerRegistry;
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
 * CDI-managed wrapper for CAEngine in Quarkus deployments.
 *
 * The CA is the most complex subsystem in Dogtag PKI, with certificate
 * issuance, revocation, CRL generation, sub-CA management, profile
 * subsystem, and security domain management. This wrapper manages the
 * real CAEngine lifecycle via CDI events and uses Quarkus
 * lifecycle management.
 */
@ApplicationScoped
public class CAEngineQuarkus {

    private static final Logger logger = LoggerFactory.getLogger(CAEngineQuarkus.class);

    private static CAEngineQuarkus INSTANCE;

    private CAEngine engine;

    public static CAEngineQuarkus getInstance() {
        return INSTANCE;
    }

    public CAEngine getEngine() {
        return engine;
    }

    void onStart(@Observes StartupEvent event) {
        INSTANCE = this;
        try {
            start();
        } catch (Throwable e) {
            logger.error("Failed to start CA engine", e);
            throw new RuntimeException("CA engine startup failed", e);
        }
    }

    void onStop(@Observes ShutdownEvent event) {
        try {
            stop();
        } catch (Throwable e) {
            logger.error("Error stopping CA engine", e);
        }
    }

    public void start() throws Exception {
        logger.info("CAEngineQuarkus: Starting CA engine");

        // Configure instance directory for Quarkus
        CMS.setInstanceConfig(new QuarkusInstanceConfig());

        // Pre-initialize JSS/CryptoManager so native library is loaded
        // before JssSubsystem static initialization references SSLCipher.
        // In Tomcat, TomcatJSS handles this; in Quarkus we do it here.
        initJSS();

        // Create the real CA engine
        engine = new CAEngine();

        // Set Quarkus socket listener registry
        engine.setSocketListenerRegistry(new QuarkusSocketListenerRegistry());

        // Start the engine (loads CS.cfg, initializes all subsystems)
        engine.start();

        logger.info("CAEngineQuarkus: CA engine started successfully");
    }

    /**
     * Pre-load the JSS native library so that SSLCipher static
     * initialization (which uses native methods) works when
     * JssSubsystem class is first loaded. In Tomcat, TomcatJSS
     * handles this; in Quarkus we load the library explicitly.
     *
     * We use System.load() with an absolute path rather than
     * System.loadLibrary() because the Quarkus bootstrap runner
     * may override java.library.path. We do NOT call
     * CryptoManager.initialize() here because JssSubsystem.init()
     * does that later during engine.start().
     */
    private void initJSS() {
        String jssLibPath = System.getProperty(
                "pki.jss.library", "/usr/lib64/jss/libjss.so");
        try {
            logger.info("CAEngineQuarkus: Loading JSS native library from {}", jssLibPath);
            System.load(jssLibPath);
            logger.info("CAEngineQuarkus: JSS native library loaded");
        } catch (UnsatisfiedLinkError e) {
            // Library might already be loaded
            if (e.getMessage() != null && e.getMessage().contains("already loaded")) {
                logger.debug("CAEngineQuarkus: JSS native library already loaded");
            } else {
                logger.error("CAEngineQuarkus: Failed to load JSS native library: {}", e.getMessage());
                throw e;
            }
        }
    }

    public void stop() throws Exception {
        logger.info("CAEngineQuarkus: Stopping CA engine");

        if (engine != null) {
            engine.shutdown();
            engine = null;
        }

        logger.info("CAEngineQuarkus: CA engine stopped");
    }

    /**
     * Convert Quarkus SecurityIdentity to PKIPrincipalCore for backward
     * compatibility with processors that check instanceof PKIPrincipalCore.
     */
    public static PKIPrincipalCore toPKIPrincipalCore(SecurityIdentity identity) {
        PKIPrincipalCore core = identity.getAttribute("pki.principal");
        if (core != null) {
            return core;
        }
        // Fallback: create minimal principal from SecurityIdentity
        String name = identity.getPrincipal().getName();
        User user = new User();
        user.setUserID(name);
        user.setFullName(name);
        return new PKIPrincipalCore(name, null, List.of(), user, null);
    }

    /**
     * Check if the authenticated user has a specific role.
     */
    public static boolean hasRole(SecurityIdentity identity, String role) {
        return identity.getRoles().contains(role);
    }

    /**
     * Get user ID from SecurityIdentity.
     */
    public static String getUserID(SecurityIdentity identity) {
        PKIPrincipalCore core = identity.getAttribute("pki.principal");
        if (core != null) {
            return core.getName();
        }
        return identity.getPrincipal().getName();
    }
}
