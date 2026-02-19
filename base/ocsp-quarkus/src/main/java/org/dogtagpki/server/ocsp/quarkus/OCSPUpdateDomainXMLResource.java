//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ocsp.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.UpdateDomainXMLResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * OCSP-specific UpdateDomainXML resource.
 * Legacy URL: /admin/ocsp/updateDomainXML
 */
@Path("admin/ocsp/updateDomainXML")
public class OCSPUpdateDomainXMLResource extends UpdateDomainXMLResourceBase {

    @Inject
    OCSPEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
