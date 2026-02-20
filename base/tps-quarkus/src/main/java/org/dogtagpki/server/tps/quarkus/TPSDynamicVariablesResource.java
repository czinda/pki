//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.DynamicVariablesResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * TPS dynamic variables resource.
 * Legacy URL: /ee/tps/dynamicVariables
 */
@Path("ee/tps/dynamicVariables")
public class TPSDynamicVariablesResource extends DynamicVariablesResourceBase {

    @Inject
    TPSEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
