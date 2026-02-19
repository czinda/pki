//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.MainPageResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * TPS main page resource.
 * Legacy URL: /admin/tps/mainPage
 */
@Path("admin/tps/mainPage")
public class TPSMainPageResource extends MainPageResourceBase {

    @Inject
    TPSEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
