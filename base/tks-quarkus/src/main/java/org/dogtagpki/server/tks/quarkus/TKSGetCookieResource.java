//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tks.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.GetCookieResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * TKS-specific GetCookie resource.
 * Legacy URL: /admin/tks/getCookie
 */
@Path("admin/tks/getCookie")
public class TKSGetCookieResource extends GetCookieResourceBase {

    @Inject
    TKSEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
