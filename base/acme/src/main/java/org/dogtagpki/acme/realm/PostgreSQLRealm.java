//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.realm;

import com.netscape.cms.realm.PKIPrincipalCore;
import com.netscape.cms.realm.PKIRealmCore;
import com.netscape.cms.realm.RealmCoreConfig;

/**
 * @author Endi S. Dewata
 */
public class PostgreSQLRealm extends PKIRealmCore {

    @Override
    public void setConfig(RealmCoreConfig config) {
        super.setConfig(config);
        if (config.getParameter("statements") == null) {
            this.config.setParameter("statements", "/usr/share/pki/acme/realm/postgresql/statements.conf");
        }
    }

    @Override
    public PKIPrincipalCore authenticate(String username, String password) {
        // TODO: implement PostgreSQL authentication
        return null;
    }

    @Override
    public void init() throws Exception {
        // TODO: initialize PostgreSQL connection
    }
}
