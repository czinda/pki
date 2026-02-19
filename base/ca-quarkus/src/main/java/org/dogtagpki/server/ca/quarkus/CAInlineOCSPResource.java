//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.quarkus.InlineOCSPResourceBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmsutil.ocsp.OCSPRequest;
import com.netscape.cmsutil.ocsp.OCSPResponse;

/**
 * CA's inline OCSP responder resource.
 * Processes OCSP requests directly within the CA.
 * Legacy URL: /ee/ca/ocsp
 */
@Path("ee/ca/ocsp")
public class CAInlineOCSPResource extends InlineOCSPResourceBase {

    private static final Logger logger = LoggerFactory.getLogger(CAInlineOCSPResource.class);

    @Inject
    CAEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }

    @Override
    protected OCSPResponse validate(OCSPRequest ocspRequest) throws Exception {
        CAEngine engine = engineQuarkus.getEngine();
        return engine.validate(engine.getCA(), ocspRequest);
    }
}
