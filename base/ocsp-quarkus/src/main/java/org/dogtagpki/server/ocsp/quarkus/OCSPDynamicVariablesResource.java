//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ocsp.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.DynamicVariablesResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * OCSP dynamic variables resource.
 * Legacy URL: /ee/ocsp/dynamicVariables
 */
@Path("ee/ocsp/dynamicVariables")
public class OCSPDynamicVariablesResource extends DynamicVariablesResourceBase {

    @Inject
    OCSPEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
