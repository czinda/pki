//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.DownloadPKCS12ResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * TPS-specific DownloadPKCS12 resource.
 * Legacy URL: /admin/tps/downloadPKCS12
 */
@Path("admin/tps/downloadPKCS12")
public class TPSDownloadPKCS12Resource extends DownloadPKCS12ResourceBase {

    @Inject
    TPSEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
