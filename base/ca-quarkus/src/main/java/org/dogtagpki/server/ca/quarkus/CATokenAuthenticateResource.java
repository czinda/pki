//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.TokenAuthenticateResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * CA-specific TokenAuthenticate resource.
 * Legacy URL: /ee/ca/tokenAuthenticate
 */
@Path("ee/ca/tokenAuthenticate")
public class CATokenAuthenticateResource extends TokenAuthenticateResourceBase {

    @Inject
    CAEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
