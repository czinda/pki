//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.quarkus;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.security.Provider;
import java.security.Security;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;

import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.quarkus.QuarkusSocketListenerRegistry;
import org.dogtagpki.server.tps.TPSEngine;
import org.dogtagpki.server.tps.TPSSubsystem;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.InitializationValues;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.util.Password;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.tps.token.TokenStatus;
import com.netscape.certsrv.user.UserResource;
import com.netscape.cms.realm.PKIPrincipalCore;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.QuarkusInstanceConfig;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmscore.usrgrp.User;

import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.StartupEvent;
import io.quarkus.security.identity.SecurityIdentity;

/**
 * CDI-managed wrapper for TPSEngine in Quarkus deployments.
 *
 * TPS extends CMSEngine and needs the full PKI infrastructure
 * (LDAP, auth, authz, token databases, connectors, etc.).
 * This wrapper manages the real TPSEngine lifecycle via CDI events
 * and uses Quarkus lifecycle management.
 *
 * Provides utility methods for profile-based authorization and
 * audit logging that replace the TPSServlet base class methods.
 */
@ApplicationScoped
public class TPSEngineQuarkus {

    private static final Logger logger = LoggerFactory.getLogger(TPSEngineQuarkus.class);

    private static TPSEngineQuarkus INSTANCE;

    private TPSEngine engine;

    public static TPSEngineQuarkus getInstance() {
        return INSTANCE;
    }

    public TPSEngine getEngine() {
        return engine;
    }

    public TPSSubsystem getSubsystem() {
        return (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
    }

    void onStart(@Observes StartupEvent event) {
        INSTANCE = this;
        try {
            start();
        } catch (Throwable e) {
            logger.error("Failed to start TPS engine", e);
            throw new RuntimeException("TPS engine startup failed", e);
        }
    }

    void onStop(@Observes ShutdownEvent event) {
        try {
            stop();
        } catch (Throwable e) {
            logger.error("Error stopping TPS engine", e);
        }
    }

    public void start() throws Exception {
        logger.info("TPSEngineQuarkus: Starting TPS engine");

        CMS.setInstanceConfig(new QuarkusInstanceConfig());

        // Pre-initialize JSS/CryptoManager so native library is loaded
        // before JssSubsystem static initialization references SSLCipher.
        // In Tomcat, TomcatJSS handles this; in Quarkus we do it here.
        initJSS();

        engine = new TPSEngine();
        engine.setSocketListenerRegistry(new QuarkusSocketListenerRegistry());
        engine.start();

        logger.info("TPSEngineQuarkus: TPS engine started successfully");
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
                logger.warn("TPSEngineQuarkus: Instance directory not set, skipping JSS init");
                return;
            }

            String certdbDir = instanceDir + File.separator + "conf"
                    + File.separator + "alias";
            if (!new File(certdbDir).exists()) {
                certdbDir = instanceDir + File.separator + "alias";
            }
            if (!new File(certdbDir).exists()) {
                logger.warn("TPSEngineQuarkus: NSS database not found, skipping JSS init");
                return;
            }

            logger.info("TPSEngineQuarkus: Pre-initializing JSS with NSS database: {}", certdbDir);
            InitializationValues iv = new InitializationValues(certdbDir);
            iv.removeSunProvider = false;
            iv.installJSSProvider = true;
            CryptoManager.initialize(iv);
            logger.info("TPSEngineQuarkus: JSS initialized successfully");

            // Login to internal token using password from password.conf
            loginInternalToken(instanceDir);

        } catch (Exception e) {
            logger.error("TPSEngineQuarkus: Failed to pre-initialize JSS", e);
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
            logger.info("TPSEngineQuarkus: Moved Mozilla-JSS provider to end of provider list");
        }
    }

    private void loginInternalToken(String instanceDir) {
        try {
            String passwordFile = instanceDir + File.separator + "conf"
                    + File.separator + "password.conf";
            if (!new File(passwordFile).exists()) {
                logger.debug("TPSEngineQuarkus: password.conf not found, skipping token login");
                return;
            }

            String internalPassword = readPassword(passwordFile, "internal");
            if (internalPassword == null) {
                logger.debug("TPSEngineQuarkus: No internal token password found");
                return;
            }

            CryptoManager cm = CryptoManager.getInstance();
            CryptoToken token = cm.getInternalKeyStorageToken();
            Password password = new Password(internalPassword.toCharArray());
            try {
                token.login(password);
                logger.info("TPSEngineQuarkus: Logged into internal token");
            } finally {
                password.clear();
            }
        } catch (Exception e) {
            logger.debug("TPSEngineQuarkus: Token login skipped: {}", e.getMessage());
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
        logger.info("TPSEngineQuarkus: Stopping TPS engine");

        if (engine != null) {
            engine.shutdown();
            engine = null;
        }

        logger.info("TPSEngineQuarkus: TPS engine stopped");
    }

    /**
     * Convert a Quarkus SecurityIdentity to a PKIPrincipalCore.
     */
    public static PKIPrincipalCore toPKIPrincipalCore(SecurityIdentity identity) {
        PKIPrincipalCore core = identity.getAttribute("pki.principal");
        if (core != null) {
            return core;
        }

        String name = identity.getPrincipal().getName();
        User user = new User();
        user.setUserID(name);
        user.setFullName(name);
        return new PKIPrincipalCore(name, null, List.of(), user, null);
    }

    /**
     * Get the list of TPS profiles authorized for the current user.
     * Replaces TPSServlet.getAuthorizedProfiles().
     *
     * This reads from the User extracted from the SecurityIdentity's PKIPrincipalCore
     * and read TPS profiles from the user record.
     */
    public static List<String> getAuthorizedProfiles(SecurityIdentity identity) {
        PKIPrincipalCore core = identity.getAttribute("pki.principal");
        if (core != null) {
            User user = (User) core.getUser();
            if (user != null) {
                List<String> profiles = user.getTpsProfiles();
                if (profiles != null && !profiles.isEmpty()) {
                    return profiles;
                }
            }
        }

        // Fallback: grant ALL_PROFILES for authenticated users without
        // explicit profile restrictions. In production, the identity
        // provider should populate TPS profiles from LDAP user attributes.
        return List.of(UserResource.ALL_PROFILES);
    }

    /**
     * Get the user ID from the SecurityIdentity for audit logging.
     */
    public static String getUserID(SecurityIdentity identity) {
        PKIPrincipalCore core = identity.getAttribute("pki.principal");
        if (core != null) {
            return core.getName();
        }
        return identity.getPrincipal().getName();
    }

    // Audit utility methods replacing TPSServlet audit methods

    public void auditConfigTokenGeneral(String status, String service,
            Map<String, String> params, String info, String userID) {
        Auditor auditor = engine.getAuditor();
        String msg = CMS.getLogMessage(
                AuditEvent.CONFIG_TOKEN_GENERAL,
                userID,
                status,
                service,
                auditor.getParamString(params),
                info);
        auditor.log(msg);
    }

    public void auditConfigTokenRecord(String status, String service,
            String tokenID, Map<String, String> params, String info, String userID) {
        Auditor auditor = engine.getAuditor();
        String msg = CMS.getLogMessage(
                AuditEvent.CONFIG_TOKEN_RECORD,
                userID,
                status,
                service,
                tokenID,
                auditor.getParamString(params),
                info);
        auditor.log(msg);
    }

    public void auditTokenStateChange(String status, TokenStatus oldState,
            TokenStatus newState, String oldReason, String newReason,
            Map<String, String> params, String info, String userID) {
        Auditor auditor = engine.getAuditor();
        String msg = CMS.getLogMessage(
                AuditEvent.TOKEN_STATE_CHANGE,
                userID,
                status,
                (oldState == null) ? "" : oldState.toString(),
                oldReason,
                (newState == null) ? "" : newState.toString(),
                newReason,
                auditor.getParamString(params),
                info);
        auditor.log(msg);
    }
}
