//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.quarkus.PortsResourceBase;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * JAX-RS resource replacing the legacy PortsServlet for CA.
 * Returns HTTP/HTTPS port information as JSON.
 *
 * Legacy URL: /ee/ca/ports
 */
@Path("ee/ca/ports")
public class CAPortsResource extends PortsResourceBase {

    @Inject
    CAEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }
}
