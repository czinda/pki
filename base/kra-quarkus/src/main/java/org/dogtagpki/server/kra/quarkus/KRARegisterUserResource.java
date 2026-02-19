//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.RegisterUserResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * KRA-specific RegisterUser resource.
 * Legacy URL: /admin/kra/registerUser
 */
@Path("admin/kra/registerUser")
public class KRARegisterUserResource extends RegisterUserResourceBase {

    @Inject
    KRAEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }

    @Override
    protected String getGroupName() {
        return "Trusted Managers";
    }
}
