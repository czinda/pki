//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.ProcessReqResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * KRA request detail display resource.
 * Legacy URL: /agent/kra/processReq
 */
@Path("agent/kra/processReq")
public class KRAProcessReqResource extends ProcessReqResourceBase {

    @Inject
    KRAEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
