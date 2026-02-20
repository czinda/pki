//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.GetConfigEntriesResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * CA-specific GetConfigEntries resource.
 * Legacy URL: /admin/ca/getConfigEntries
 */
@Path("admin/ca/getConfigEntries")
public class CAGetConfigEntriesResource extends GetConfigEntriesResourceBase {

    @Inject
    CAEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
