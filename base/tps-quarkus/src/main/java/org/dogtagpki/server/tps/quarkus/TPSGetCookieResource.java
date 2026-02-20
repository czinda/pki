//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.GetCookieResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * TPS-specific GetCookie resource.
 * Legacy URL: /admin/tps/getCookie
 */
@Path("admin/tps/getCookie")
public class TPSGetCookieResource extends GetCookieResourceBase {

    @Inject
    TPSEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
