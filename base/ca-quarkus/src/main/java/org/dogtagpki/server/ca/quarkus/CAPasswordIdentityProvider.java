//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.dogtagpki.server.quarkus.PKIPasswordIdentityProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cms.realm.PKIAuthenticator;
import com.netscape.cms.realm.PKIPrincipalCore;

/**
 * CA-specific identity provider for password authentication.
 *
 * Delegates to PKIAuthenticator to authenticate against the
 * PKI internal user database (LDAP-backed).
 */
@ApplicationScoped
public class CAPasswordIdentityProvider extends PKIPasswordIdentityProvider {

    private static final Logger logger = LoggerFactory.getLogger(CAPasswordIdentityProvider.class);

    @Inject
    CAEngineQuarkus engineQuarkus;

    @Override
    protected PKIPrincipalCore authenticateByPassword(String username, String password) {
        try {
            PKIAuthenticator authenticator = new PKIAuthenticator(engineQuarkus.getEngine());
            return authenticator.authenticateByPassword(username, password);
        } catch (Exception e) {
            logger.error("CAPasswordIdentityProvider: Authentication failed for user {}: {}",
                    username, e.getMessage());
            return null;
        }
    }
}
