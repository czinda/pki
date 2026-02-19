//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ocsp.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.GetConfigEntriesResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * OCSP-specific GetConfigEntries resource.
 * Legacy URL: /admin/ocsp/getConfigEntries
 */
@Path("admin/ocsp/getConfigEntries")
public class OCSPGetConfigEntriesResource extends GetConfigEntriesResourceBase {

    @Inject
    OCSPEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
