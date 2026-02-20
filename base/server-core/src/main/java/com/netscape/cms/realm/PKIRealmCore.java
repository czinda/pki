//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cms.realm;

import java.security.Principal;
import java.security.cert.X509Certificate;

/**
 * Abstract base for PKI realms.
 *
 * Provides authentication methods that return PKIPrincipalCore.
 * Realm implementations should extend this class.
 */
public abstract class PKIRealmCore {

    protected RealmCoreConfig config;

    public RealmCoreConfig getConfig() {
        return config;
    }

    public void setConfig(RealmCoreConfig config) {
        this.config = config;
    }

    /**
     * Initialize the realm. Called after config is set.
     */
    public abstract void init() throws Exception;

    /**
     * Authenticate a user by username and password.
     *
     * @return a PKIPrincipalCore on success, or null on failure
     */
    public abstract PKIPrincipalCore authenticate(String username, String password);

    /**
     * Authenticate a user by X.509 certificate chain.
     *
     * @return a PKIPrincipalCore on success, or null on failure
     */
    public PKIPrincipalCore authenticate(X509Certificate[] certs) {
        return null;
    }

    /**
     * Shut down realm resources.
     */
    public void stop() throws Exception {
    }
}
