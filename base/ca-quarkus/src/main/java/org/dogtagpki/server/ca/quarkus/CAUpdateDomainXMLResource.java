//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.UpdateDomainXMLResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * CA-specific UpdateDomainXML resource.
 * Legacy URL: /admin/ca/updateDomainXML
 */
@Path("admin/ca/updateDomainXML")
public class CAUpdateDomainXMLResource extends UpdateDomainXMLResourceBase {

    @Inject
    CAEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
