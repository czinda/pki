//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.UpdateDomainXMLResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * TPS-specific UpdateDomainXML resource.
 * Legacy URL: /admin/tps/updateDomainXML
 */
@Path("admin/tps/updateDomainXML")
public class TPSUpdateDomainXMLResource extends UpdateDomainXMLResourceBase {

    @Inject
    TPSEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
