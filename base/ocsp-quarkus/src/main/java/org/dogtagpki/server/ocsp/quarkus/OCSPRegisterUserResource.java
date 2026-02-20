//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ocsp.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.RegisterUserResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * OCSP-specific RegisterUser resource.
 * Legacy URL: /admin/ocsp/registerUser
 */
@Path("admin/ocsp/registerUser")
public class OCSPRegisterUserResource extends RegisterUserResourceBase {

    @Inject
    OCSPEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }

    @Override
    protected String getGroupName() {
        return "Trusted Managers";
    }
}
