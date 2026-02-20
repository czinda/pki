//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.QueryReqResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * KRA request query/listing resource.
 * Legacy URL: /agent/kra/queryReq
 */
@Path("agent/kra/queryReq")
public class KRAQueryReqResource extends QueryReqResourceBase {

    @Inject
    KRAEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
