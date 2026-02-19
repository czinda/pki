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
public class InMemoryRealm extends PKIRealmCore {

    @Override
    public PKIPrincipalCore authenticate(String username, String password) {
        return null;
    }

    @Override
    public void init() throws Exception {
    }
}
