//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.realm;

import com.netscape.cms.realm.PKIPrincipalCore;
import com.netscape.cms.realm.PKIRealmCore;

/**
 * @author Endi S. Dewata
 */
public class LDAPRealm extends PKIRealmCore {

    @Override
    public PKIPrincipalCore authenticate(String username, String password) {
        // TODO: implement LDAP authentication
        return null;
    }

    @Override
    public void init() throws Exception {
        // TODO: initialize LDAP connection and create realm subtrees
    }
}
