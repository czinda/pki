//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.SystemInfoResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * KRA system info resource.
 * Legacy URL: /admin/kra/systemInfo
 */
@Path("admin/kra/systemInfo")
public class KRASystemInfoResource extends SystemInfoResourceBase {

    @Inject
    KRAEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
