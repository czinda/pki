//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.TokenAuthenticateResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * KRA-specific TokenAuthenticate resource.
 * Legacy URL: /ee/kra/tokenAuthenticate
 */
@Path("ee/kra/tokenAuthenticate")
public class KRATokenAuthenticateResource extends TokenAuthenticateResourceBase {

    @Inject
    KRAEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
