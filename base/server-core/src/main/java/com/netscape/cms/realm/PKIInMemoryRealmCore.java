//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cms.realm;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Container-agnostic in-memory realm.
 *
 * Authenticates a single user with a configured username/password.
 * Used for standalone testing and simple deployments.
 */
public class PKIInMemoryRealmCore extends PKIRealmCore {

    private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PKIInMemoryRealmCore.class);

    private String username;
    private String password;
    private List<String> roles;

    @Override
    public void init() throws Exception {
        username = config.getParameter("username");
        password = config.getParameter("password");
        String roleList = config.getParameter("roles");

        if (roleList == null) {
            roles = new ArrayList<>();
            roles.add("Administrators");
        } else {
            roles = Stream.of(roleList.split(",")).map(String::trim).collect(Collectors.toList());
        }
    }

    @Override
    public PKIPrincipalCore authenticate(String username, String password) {

        logger.info("Authenticating user " + username + " with password");

        if (!this.username.equals(username)) {
            logger.warn("Unable to authenticate user " + username + ": User not found");
            return null;
        }

        if (!this.password.equals(password)) {
            logger.warn("Unable to authenticate user " + username + ": Invalid password");
            return null;
        }

        logger.info("User " + username + " authenticated");

        return new PKIPrincipalCore(username, null, roles);
    }
}
