//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.GetCookieResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * KRA-specific GetCookie resource.
 * Legacy URL: /admin/kra/getCookie
 */
@Path("admin/kra/getCookie")
public class KRAGetCookieResource extends GetCookieResourceBase {

    @Inject
    KRAEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
