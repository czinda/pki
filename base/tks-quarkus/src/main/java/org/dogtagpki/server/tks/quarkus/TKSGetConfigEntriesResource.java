//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tks.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.GetConfigEntriesResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * TKS-specific GetConfigEntries resource.
 * Legacy URL: /admin/tks/getConfigEntries
 */
@Path("admin/tks/getConfigEntries")
public class TKSGetConfigEntriesResource extends GetConfigEntriesResourceBase {

    @Inject
    TKSEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
