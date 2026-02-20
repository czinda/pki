//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tks.quarkus;

import java.security.cert.X509Certificate;

import jakarta.enterprise.context.ApplicationScoped;

import org.dogtagpki.server.quarkus.PKIIdentityProvider;
import com.netscape.cms.realm.PKIPrincipalCore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@ApplicationScoped
public class TKSIdentityProvider extends PKIIdentityProvider {

    private static final Logger logger = LoggerFactory.getLogger(TKSIdentityProvider.class);

    @Override
    protected PKIPrincipalCore authenticateCertificate(X509Certificate cert) {
        String dn = cert.getSubjectX500Principal().getName();
        String cn = extractCN(dn);
        String principalName = cn != null ? cn : dn;

        logger.info("TKSIdentityProvider: Authenticated certificate for: {}", principalName);

        return new PKIPrincipalCore(principalName, null, java.util.List.of("TKS Agents"));
    }
}
