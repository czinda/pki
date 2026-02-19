//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.RegisterUserResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * CA-specific RegisterUser resource.
 * Legacy URL: /admin/ca/registerUser
 */
@Path("admin/ca/registerUser")
public class CARegisterUserResource extends RegisterUserResourceBase {

    @Inject
    CAEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }

    @Override
    protected String getGroupName() {
        return "Trusted Managers";
    }
}
