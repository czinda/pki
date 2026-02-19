//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.GetConfigEntriesResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * KRA-specific GetConfigEntries resource.
 * Legacy URL: /admin/kra/getConfigEntries
 */
@Path("admin/kra/getConfigEntries")
public class KRAGetConfigEntriesResource extends GetConfigEntriesResourceBase {

    @Inject
    KRAEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
