//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.quarkus.GetOCSPInfoResourceBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.ocsp.IOCSPService;

/**
 * CA-specific JAX-RS resource for OCSP info, extending the shared
 * GetOCSPInfoResourceBase. The CA's CertificateAuthority class
 * implements IOCSPService, so this resource provides OCSP statistics
 * for the CA's built-in OCSP responder.
 * Legacy URL: /ee/ca/getOCSPInfo
 */
@Path("ee/ca/getOCSPInfo")
public class CAGetOCSPInfoResource extends GetOCSPInfoResourceBase {

    private static final Logger logger = LoggerFactory.getLogger(CAGetOCSPInfoResource.class);

    @Inject
    CAEngineQuarkus engineQuarkus;

    @Override
    protected IOCSPService getOCSPService() {
        CAEngine engine = engineQuarkus.getEngine();
        CertificateAuthority ca = engine.getCA();

        if (ca instanceof IOCSPService) {
            return (IOCSPService) ca;
        }

        logger.warn("CAGetOCSPInfoResource: CA does not implement IOCSPService");
        return null;
    }
}
