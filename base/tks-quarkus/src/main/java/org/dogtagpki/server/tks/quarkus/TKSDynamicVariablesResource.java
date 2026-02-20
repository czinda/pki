//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tks.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.DynamicVariablesResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * TKS dynamic variables resource.
 * Legacy URL: /ee/tks/dynamicVariables
 */
@Path("ee/tks/dynamicVariables")
public class TKSDynamicVariablesResource extends DynamicVariablesResourceBase {

    @Inject
    TKSEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
