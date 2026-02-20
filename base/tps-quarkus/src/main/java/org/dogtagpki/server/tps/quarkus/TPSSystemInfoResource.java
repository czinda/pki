//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.SystemInfoResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * TPS system info resource.
 * Legacy URL: /admin/tps/systemInfo
 */
@Path("admin/tps/systemInfo")
public class TPSSystemInfoResource extends SystemInfoResourceBase {

    @Inject
    TPSEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
