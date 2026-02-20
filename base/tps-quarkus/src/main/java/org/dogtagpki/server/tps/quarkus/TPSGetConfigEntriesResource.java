//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.GetConfigEntriesResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * TPS-specific GetConfigEntries resource.
 * Legacy URL: /admin/tps/getConfigEntries
 */
@Path("admin/tps/getConfigEntries")
public class TPSGetConfigEntriesResource extends GetConfigEntriesResourceBase {

    @Inject
    TPSEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
