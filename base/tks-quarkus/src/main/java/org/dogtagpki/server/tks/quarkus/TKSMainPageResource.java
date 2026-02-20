//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tks.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.MainPageResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * TKS main page resource.
 * Legacy URL: /admin/tks/mainPage
 */
@Path("admin/tks/mainPage")
public class TKSMainPageResource extends MainPageResourceBase {

    @Inject
    TKSEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
