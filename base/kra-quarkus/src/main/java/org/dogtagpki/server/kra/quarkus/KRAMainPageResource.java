//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.MainPageResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * KRA main page resource.
 * Legacy URL: /admin/kra/mainPage
 */
@Path("admin/kra/mainPage")
public class KRAMainPageResource extends MainPageResourceBase {

    @Inject
    KRAEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
