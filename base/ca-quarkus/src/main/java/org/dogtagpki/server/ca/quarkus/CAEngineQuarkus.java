//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.security.Provider;
import java.security.Security;
import java.util.List;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.quarkus.QuarkusSocketListenerRegistry;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.InitializationValues;
import org.mozilla.jss.crypto.AlreadyInitializedException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.util.Password;
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

        // Pre-initialize JSS/CryptoManager and login to internal token.
        // In Tomcat, TomcatJSS handles JSS initialization and token login
        // before the engine starts. In Quarkus we do it here.
        // JssSubsystem.init() will get AlreadyInitializedException and
        // skip re-initialization.
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
     * Pre-initialize JSS for Quarkus. This performs the same role that
     * TomcatJSS plays in Tomcat deployments:
     *
     * 1. Load JSS native library (so SSLCipher static init works)
     * 2. Initialize CryptoManager with the NSS database
     * 3. Login to the internal token using password.conf
     *
     * When JssSubsystem.init() runs later during engine.start(), it
     * will get AlreadyInitializedException and skip re-initialization.
     */
    private void initJSS() {
        // Step 1: Load native library using absolute path.
        // System.loadLibrary("jss") doesn't work because the Quarkus
        // bootstrap runner may override java.library.path.
        String jssLibPath = System.getProperty(
                "pki.jss.library", "/usr/lib64/jss/libjss.so");
        try {
            logger.info("CAEngineQuarkus: Loading JSS native library from {}", jssLibPath);
            System.load(jssLibPath);
            logger.info("CAEngineQuarkus: JSS native library loaded");
        } catch (UnsatisfiedLinkError e) {
            if (e.getMessage() != null && e.getMessage().contains("already loaded")) {
                logger.debug("CAEngineQuarkus: JSS native library already loaded");
            } else {
                logger.error("CAEngineQuarkus: Failed to load JSS native library: {}", e.getMessage());
                throw e;
            }
        }

        // Step 2: Initialize CryptoManager with NSS database.
        // Use pki.nss.database system property (set by startup script)
        // or derive from instance directory.
        String nssDatabase = System.getProperty("pki.nss.database");
        if (nssDatabase == null) {
            String instanceDir = CMS.getInstanceDir();
            if (instanceDir != null) {
                nssDatabase = instanceDir + File.separator + "conf"
                        + File.separator + "alias";
                if (!new File(nssDatabase).exists()) {
                    nssDatabase = instanceDir + File.separator + "alias";
                }
            }
        }

        if (nssDatabase == null || !new File(nssDatabase).exists()) {
            logger.warn("CAEngineQuarkus: NSS database not found, skipping CryptoManager init");
            return;
        }

        try {
            logger.info("CAEngineQuarkus: Initializing CryptoManager with NSS database: {}", nssDatabase);
            // Use same parameters as JssSubsystem.init()
            InitializationValues iv = new InitializationValues(nssDatabase, "", "", "secmod.db");
            iv.removeSunProvider = false;
            iv.installJSSProvider = true;
            CryptoManager.initialize(iv);
            logger.info("CAEngineQuarkus: CryptoManager initialized successfully");
        } catch (AlreadyInitializedException e) {
            logger.debug("CAEngineQuarkus: CryptoManager already initialized");
        } catch (Exception e) {
            logger.error("CAEngineQuarkus: Failed to initialize CryptoManager", e);
            throw new RuntimeException("CryptoManager initialization failed", e);
        }

        // JSS CryptoManager.initialize() inserts the Mozilla-JSS provider at
        // position 1 (highest priority). This causes Vert.x TLS to fail because
        // JSS-backed keys return null from getFormat(), which triggers a
        // NullPointerException in PKCS12KeyStore.setKeyEntry().
        //
        // Move JSS to the end of the provider list so that standard JCA/JSSE
        // providers (SunRsaSign, SunJSSE, SunJCE) are used by default for TLS
        // operations. JSS remains available for explicit use by PKI code that
        // requests the "Mozilla-JSS" provider by name.
        Provider jssProvider = Security.getProvider("Mozilla-JSS");
        if (jssProvider != null) {
            Security.removeProvider("Mozilla-JSS");
            Security.addProvider(jssProvider);
            logger.info("CAEngineQuarkus: Moved Mozilla-JSS provider to end of provider list");
        }

        // Step 3: Login to internal token using password from password.conf
        loginInternalToken();
    }

    private void loginInternalToken() {
        try {
            String instanceDir = CMS.getInstanceDir();
            if (instanceDir == null) {
                return;
            }

            String passwordFile = instanceDir + File.separator + "conf"
                    + File.separator + "password.conf";
            if (!new File(passwordFile).exists()) {
                logger.debug("CAEngineQuarkus: password.conf not found, skipping token login");
                return;
            }

            String internalPassword = readPassword(passwordFile, "internal");
            if (internalPassword == null) {
                logger.debug("CAEngineQuarkus: No internal token password found");
                return;
            }

            CryptoManager cm = CryptoManager.getInstance();
            CryptoToken token = cm.getInternalKeyStorageToken();

            if (token.isLoggedIn()) {
                logger.debug("CAEngineQuarkus: Internal token already logged in");
                return;
            }

            Password password = new Password(internalPassword.toCharArray());
            try {
                token.login(password);
                logger.info("CAEngineQuarkus: Logged into internal token");
            } finally {
                password.clear();
            }
        } catch (Exception e) {
            logger.warn("CAEngineQuarkus: Token login failed: {}", e.getMessage());
        }
    }

    private String readPassword(String passwordFile, String tag) throws Exception {
        try (BufferedReader reader = new BufferedReader(new FileReader(passwordFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                int pos = line.indexOf('=');
                if (pos < 0) continue;
                String key = line.substring(0, pos).trim();
                String value = line.substring(pos + 1).trim();
                if (key.equals(tag)) {
                    return value;
                }
            }
        }
        return null;
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
