//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.DownloadPKCS12ResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * CA-specific DownloadPKCS12 resource.
 * Legacy URL: /admin/ca/downloadPKCS12
 */
@Path("admin/ca/downloadPKCS12")
public class CADownloadPKCS12Resource extends DownloadPKCS12ResourceBase {

    @Inject
    CAEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
