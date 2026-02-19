//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

import org.dogtagpki.server.kra.KRAEngine;
import org.dogtagpki.server.quarkus.UpdateNumberRangeResourceBase;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.dbs.Repository;

/**
 * KRA-specific UpdateNumberRange resource.
 * Legacy URL: /admin/kra/updateNumberRange
 */
@Path("admin/kra/updateNumberRange")
public class KRAUpdateNumberRangeResource extends UpdateNumberRangeResourceBase {

    @Inject
    KRAEngineQuarkus engineQuarkus;

    @Override
    protected CMSEngine getEngine() {
        return engineQuarkus.getEngine();
    }

    @Override
    protected Repository getRepository(String type) throws EBaseException {
        KRAEngine engine = engineQuarkus.getEngine();

        if ("request".equals(type)) {
            return engine.getKeyRequestRepository();
        } else if ("serialNo".equals(type)) {
            return engine.getKeyRepository();
        } else if ("replicaId".equals(type)) {
            return engine.getReplicaIDRepository();
        }

        throw new EBaseException("Unsupported repository: " + type);
    }
}
