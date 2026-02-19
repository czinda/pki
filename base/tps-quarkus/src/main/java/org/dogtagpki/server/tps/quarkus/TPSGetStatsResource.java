//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.GetStatsResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * TPS statistics resource.
 * Legacy URL: /admin/tps/getStats
 */
@Path("admin/tps/getStats")
public class TPSGetStatsResource extends GetStatsResourceBase {

    @Inject
    TPSEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
