//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.DynamicVariablesResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * KRA dynamic variables resource.
 * Legacy URL: /ee/kra/dynamicVariables
 */
@Path("ee/kra/dynamicVariables")
public class KRADynamicVariablesResource extends DynamicVariablesResourceBase {

    @Inject
    KRAEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
