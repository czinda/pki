//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ocsp.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.GetCookieResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * OCSP-specific GetCookie resource.
 * Legacy URL: /admin/ocsp/getCookie
 */
@Path("admin/ocsp/getCookie")
public class OCSPGetCookieResource extends GetCookieResourceBase {

    @Inject
    OCSPEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
