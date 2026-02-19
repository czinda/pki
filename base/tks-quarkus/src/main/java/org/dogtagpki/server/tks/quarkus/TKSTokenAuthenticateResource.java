//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tks.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.TokenAuthenticateResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * TKS-specific TokenAuthenticate resource.
 * Legacy URL: /ee/tks/tokenAuthenticate
 */
@Path("ee/tks/tokenAuthenticate")
public class TKSTokenAuthenticateResource extends TokenAuthenticateResourceBase {

    @Inject
    TKSEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
