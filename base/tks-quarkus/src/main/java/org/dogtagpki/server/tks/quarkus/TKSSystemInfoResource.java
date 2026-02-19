//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tks.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.SystemInfoResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * TKS system info resource.
 * Legacy URL: /admin/tks/systemInfo
 */
@Path("admin/tks/systemInfo")
public class TKSSystemInfoResource extends SystemInfoResourceBase {

    @Inject
    TKSEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
