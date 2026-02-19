//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ocsp.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.GetStatsResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * OCSP statistics resource.
 * Legacy URL: /admin/ocsp/getStats
 */
@Path("admin/ocsp/getStats")
public class OCSPGetStatsResource extends GetStatsResourceBase {

    @Inject
    OCSPEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
