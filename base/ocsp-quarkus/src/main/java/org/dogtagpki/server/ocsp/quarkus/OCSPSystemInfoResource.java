//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ocsp.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.SystemInfoResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * OCSP system info resource.
 * Legacy URL: /admin/ocsp/systemInfo
 */
@Path("admin/ocsp/systemInfo")
public class OCSPSystemInfoResource extends SystemInfoResourceBase {

    @Inject
    OCSPEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
