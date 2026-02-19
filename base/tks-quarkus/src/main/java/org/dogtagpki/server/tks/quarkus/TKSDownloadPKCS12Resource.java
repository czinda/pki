//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tks.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.DownloadPKCS12ResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * TKS-specific DownloadPKCS12 resource.
 * Legacy URL: /admin/tks/downloadPKCS12
 */
@Path("admin/tks/downloadPKCS12")
public class TKSDownloadPKCS12Resource extends DownloadPKCS12ResourceBase {

    @Inject
    TKSEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
