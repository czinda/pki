//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.quarkus;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.apps.PreOpConfig;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * Abstract base JAX-RS resource replacing the legacy DownloadPKCS12 CMSServlet.
 * Returns the PKCS#12 file generated during subsystem deployment.
 * Used during pkispawn for exporting system keys.
 *
 * Each subsystem extends this with a concrete @Path annotation.
 */
public abstract class DownloadPKCS12ResourceBase {

    private static final Logger logger = LoggerFactory.getLogger(DownloadPKCS12ResourceBase.class);

    protected abstract CMSEngine getEngine();

    @GET
    @Produces("application/x-pkcs12")
    public Response downloadPKCS12() {

        CMSEngine engine = getEngine();
        EngineConfig cs = engine.getConfig();

        try {
            PreOpConfig preopConfig = cs.getPreOpConfig();
            String str = preopConfig.getString("pkcs12");
            byte[] pkcs12 = CryptoUtil.string2byte(str);
            return Response.ok(pkcs12, "application/x-pkcs12").build();
        } catch (Exception e) {
            logger.warn("DownloadPKCS12ResourceBase: {}", e.getMessage(), e);
            return Response.serverError().build();
        }
    }
}
