//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.GetStatsResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * KRA statistics resource.
 * Legacy URL: /admin/kra/getStats
 */
@Path("admin/kra/getStats")
public class KRAGetStatsResource extends GetStatsResourceBase {

    @Inject
    KRAEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
