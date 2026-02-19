//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.UpdateDomainXMLResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * KRA-specific UpdateDomainXML resource.
 * Legacy URL: /admin/kra/updateDomainXML
 */
@Path("admin/kra/updateDomainXML")
public class KRAUpdateDomainXMLResource extends UpdateDomainXMLResourceBase {

    @Inject
    KRAEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
