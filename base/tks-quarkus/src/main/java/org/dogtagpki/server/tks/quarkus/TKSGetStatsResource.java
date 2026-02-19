//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tks.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.GetStatsResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * TKS statistics resource.
 * Legacy URL: /admin/tks/getStats
 */
@Path("admin/tks/getStats")
public class TKSGetStatsResource extends GetStatsResourceBase {

    @Inject
    TKSEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
