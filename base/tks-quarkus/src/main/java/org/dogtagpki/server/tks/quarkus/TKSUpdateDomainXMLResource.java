//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tks.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.UpdateDomainXMLResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * TKS-specific UpdateDomainXML resource.
 * Legacy URL: /admin/tks/updateDomainXML
 */
@Path("admin/tks/updateDomainXML")
public class TKSUpdateDomainXMLResource extends UpdateDomainXMLResourceBase {

    @Inject
    TKSEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
