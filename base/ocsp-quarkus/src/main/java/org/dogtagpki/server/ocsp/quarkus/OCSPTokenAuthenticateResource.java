//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ocsp.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.TokenAuthenticateResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * OCSP-specific TokenAuthenticate resource.
 * Legacy URL: /ee/ocsp/tokenAuthenticate
 */
@Path("ee/ocsp/tokenAuthenticate")
public class OCSPTokenAuthenticateResource extends TokenAuthenticateResourceBase {

    @Inject
    OCSPEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
