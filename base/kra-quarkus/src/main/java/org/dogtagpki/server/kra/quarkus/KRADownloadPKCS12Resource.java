//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.DownloadPKCS12ResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * KRA-specific DownloadPKCS12 resource.
 * Legacy URL: /admin/kra/downloadPKCS12
 */
@Path("admin/kra/downloadPKCS12")
public class KRADownloadPKCS12Resource extends DownloadPKCS12ResourceBase {

    @Inject
    KRAEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
