//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tks.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.RegisterUserResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * TKS-specific RegisterUser resource.
 * Legacy URL: /admin/tks/registerUser
 */
@Path("admin/tks/registerUser")
public class TKSRegisterUserResource extends RegisterUserResourceBase {

    @Inject
    TKSEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }

    @Override
    protected String getGroupName() {
        return "Trusted Managers";
    }
}
