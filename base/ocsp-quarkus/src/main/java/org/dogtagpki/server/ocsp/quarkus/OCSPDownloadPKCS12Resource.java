//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ocsp.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.DownloadPKCS12ResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * OCSP-specific DownloadPKCS12 resource.
 * Legacy URL: /admin/ocsp/downloadPKCS12
 */
@Path("admin/ocsp/downloadPKCS12")
public class OCSPDownloadPKCS12Resource extends DownloadPKCS12ResourceBase {

    @Inject
    OCSPEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
