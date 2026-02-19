//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.quarkus.UpdateNumberRangeResourceBase;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.dbs.Repository;

/**
 * CA-specific UpdateNumberRange resource.
 * Legacy URL: /admin/ca/updateNumberRange
 */
@Path("admin/ca/updateNumberRange")
public class CAUpdateNumberRangeResource extends UpdateNumberRangeResourceBase {

    @Inject
    CAEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }

    @Override
    protected Repository getRepository(String type) throws EBaseException {
        CAEngine engine = engineQuarkus.getEngine();

        if ("request".equals(type)) {
            return engine.getCertRequestRepository();
        } else if ("serialNo".equals(type)) {
            return engine.getCertificateRepository();
        } else if ("replicaId".equals(type)) {
            return engine.getReplicaIDRepository();
        }

        throw new EBaseException("Unsupported repository: " + type);
    }
}
