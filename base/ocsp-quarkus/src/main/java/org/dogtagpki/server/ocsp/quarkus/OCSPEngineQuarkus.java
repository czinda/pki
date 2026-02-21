//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ocsp.quarkus;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.security.Provider;
import java.security.Security;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;

import org.dogtagpki.server.ocsp.OCSPEngine;
import org.dogtagpki.server.quarkus.QuarkusSocketListenerRegistry;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.InitializationValues;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.util.Password;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.QuarkusInstanceConfig;

import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.StartupEvent;

/**
 * CDI-managed wrapper for OCSPEngine in Quarkus deployments.
 *
 * Unlike ACME which has a standalone engine, OCSP extends CMSEngine
 * and needs the full PKI infrastructure (LDAP, auth, authz, etc.).
 * This wrapper manages the real OCSPEngine lifecycle via CDI events
 * and uses Quarkus lifecycle management.
 */
@ApplicationScoped
public class OCSPEngineQuarkus {

    private static final Logger logger = LoggerFactory.getLogger(OCSPEngineQuarkus.class);

    private static OCSPEngineQuarkus INSTANCE;

    private OCSPEngine engine;

    public static OCSPEngineQuarkus getInstance() {
        return INSTANCE;
    }

    public OCSPEngine getEngine() {
        return engine;
    }

    void onStart(@Observes StartupEvent event) {
        INSTANCE = this;
        try {
            start();
        } catch (Throwable e) {
            logger.error("Failed to start OCSP engine", e);
            throw new RuntimeException("OCSP engine startup failed", e);
        }
    }

    void onStop(@Observes ShutdownEvent event) {
        try {
            stop();
        } catch (Throwable e) {
            logger.error("Error stopping OCSP engine", e);
        }
    }

    public void start() throws Exception {
        logger.info("OCSPEngineQuarkus: Starting OCSP engine");

        // Configure instance directory for Quarkus
        CMS.setInstanceConfig(new QuarkusInstanceConfig());

        // Pre-initialize JSS/CryptoManager so native library is loaded
        // before JssSubsystem static initialization references SSLCipher.
        // In Tomcat, TomcatJSS handles this; in Quarkus we do it here.
        initJSS();

        // Create the real OCSP engine
        engine = new OCSPEngine();

        // Set Quarkus socket listener registry
        engine.setSocketListenerRegistry(new QuarkusSocketListenerRegistry());

        // Start the engine (loads CS.cfg, initializes all subsystems)
        engine.start();

        logger.info("OCSPEngineQuarkus: OCSP engine started successfully");
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
                logger.warn("OCSPEngineQuarkus: Instance directory not set, skipping JSS init");
                return;
            }

            String certdbDir = instanceDir + File.separator + "conf"
                    + File.separator + "alias";
            if (!new File(certdbDir).exists()) {
                certdbDir = instanceDir + File.separator + "alias";
            }
            if (!new File(certdbDir).exists()) {
                logger.warn("OCSPEngineQuarkus: NSS database not found, skipping JSS init");
                return;
            }

            logger.info("OCSPEngineQuarkus: Pre-initializing JSS with NSS database: {}", certdbDir);
            InitializationValues iv = new InitializationValues(certdbDir);
            iv.removeSunProvider = false;
            iv.installJSSProvider = true;
            CryptoManager.initialize(iv);
            logger.info("OCSPEngineQuarkus: JSS initialized successfully");

            // Login to internal token using password from password.conf
            loginInternalToken(instanceDir);

        } catch (Exception e) {
            logger.error("OCSPEngineQuarkus: Failed to pre-initialize JSS", e);
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
            logger.info("OCSPEngineQuarkus: Moved Mozilla-JSS provider to end of provider list");
        }
    }

    private void loginInternalToken(String instanceDir) {
        try {
            String passwordFile = instanceDir + File.separator + "conf"
                    + File.separator + "password.conf";
            if (!new File(passwordFile).exists()) {
                logger.debug("OCSPEngineQuarkus: password.conf not found, skipping token login");
                return;
            }

            String internalPassword = readPassword(passwordFile, "internal");
            if (internalPassword == null) {
                logger.debug("OCSPEngineQuarkus: No internal token password found");
                return;
            }

            CryptoManager cm = CryptoManager.getInstance();
            CryptoToken token = cm.getInternalKeyStorageToken();
            Password password = new Password(internalPassword.toCharArray());
            try {
                token.login(password);
                logger.info("OCSPEngineQuarkus: Logged into internal token");
            } finally {
                password.clear();
            }
        } catch (Exception e) {
            logger.debug("OCSPEngineQuarkus: Token login skipped: {}", e.getMessage());
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
        logger.info("OCSPEngineQuarkus: Stopping OCSP engine");

        if (engine != null) {
            engine.shutdown();
            engine = null;
        }

        logger.info("OCSPEngineQuarkus: OCSP engine stopped");
    }
}
