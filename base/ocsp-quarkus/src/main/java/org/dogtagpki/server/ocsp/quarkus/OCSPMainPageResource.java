//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ocsp.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.MainPageResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * OCSP main page resource.
 * Legacy URL: /admin/ocsp/mainPage
 */
@Path("admin/ocsp/mainPage")
public class OCSPMainPageResource extends MainPageResourceBase {

    @Inject
    OCSPEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
