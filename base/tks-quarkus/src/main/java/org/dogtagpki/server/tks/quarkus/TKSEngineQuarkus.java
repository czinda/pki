//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tks.quarkus;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.security.Provider;
import java.security.Security;
import java.util.List;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;

import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.quarkus.QuarkusSocketListenerRegistry;
import org.dogtagpki.server.tks.TKSEngine;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.InitializationValues;
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
        CMS.setInstanceConfig(new QuarkusInstanceConfig());

        // Pre-initialize JSS/CryptoManager so native library is loaded
        // before JssSubsystem static initialization references SSLCipher.
        // In Tomcat, TomcatJSS handles this; in Quarkus we do it here.
        initJSS();

        // Create the real TKS engine
        engine = new TKSEngine();

        // Set Quarkus socket listener registry
        engine.setSocketListenerRegistry(new QuarkusSocketListenerRegistry());

        // Start the engine (loads CS.cfg, initializes all subsystems)
        engine.start();

        logger.info("TKSEngineQuarkus: TKS engine started successfully");
    }

    /**
     * Pre-initialize JSS with the NSS database and login to the
     * internal token. In Tomcat, TomcatJSS handles JSS initialization
     * and token login; in Quarkus we do it here before the engine starts.
     */
    private void initJSS() {
        try {
            String instanceDir = CMS.getInstanceDir();
            if (instanceDir == null) {
                logger.warn("TKSEngineQuarkus: Instance directory not set, skipping JSS init");
                return;
            }

            String certdbDir = instanceDir + File.separator + "conf"
                    + File.separator + "alias";
            if (!new File(certdbDir).exists()) {
                certdbDir = instanceDir + File.separator + "alias";
            }
            if (!new File(certdbDir).exists()) {
                logger.warn("TKSEngineQuarkus: NSS database not found, skipping JSS init");
                return;
            }

            logger.info("TKSEngineQuarkus: Pre-initializing JSS with NSS database: {}", certdbDir);
            InitializationValues iv = new InitializationValues(certdbDir);
            iv.removeSunProvider = false;
            iv.installJSSProvider = true;
            CryptoManager.initialize(iv);
            logger.info("TKSEngineQuarkus: JSS initialized successfully");

            // Login to internal token using password from password.conf
            loginInternalToken(instanceDir);

        } catch (Exception e) {
            logger.error("TKSEngineQuarkus: Failed to pre-initialize JSS", e);
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
            logger.info("TKSEngineQuarkus: Moved Mozilla-JSS provider to end of provider list");
        }
    }

    private void loginInternalToken(String instanceDir) {
        try {
            String passwordFile = instanceDir + File.separator + "conf"
                    + File.separator + "password.conf";
            if (!new File(passwordFile).exists()) {
                logger.debug("TKSEngineQuarkus: password.conf not found, skipping token login");
                return;
            }

            String internalPassword = readPassword(passwordFile, "internal");
            if (internalPassword == null) {
                logger.debug("TKSEngineQuarkus: No internal token password found");
                return;
            }

            CryptoManager cm = CryptoManager.getInstance();
            CryptoToken token = cm.getInternalKeyStorageToken();
            Password password = new Password(internalPassword.toCharArray());
            try {
                token.login(password);
                logger.info("TKSEngineQuarkus: Logged into internal token");
            } finally {
                password.clear();
            }
        } catch (Exception e) {
            logger.debug("TKSEngineQuarkus: Token login skipped: {}", e.getMessage());
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
