//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.GetCookieResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * CA-specific GetCookie resource.
 * Legacy URL: /admin/ca/getCookie
 */
@Path("admin/ca/getCookie")
public class CAGetCookieResource extends GetCookieResourceBase {

    @Inject
    CAEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
