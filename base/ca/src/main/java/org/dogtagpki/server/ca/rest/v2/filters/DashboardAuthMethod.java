// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2024 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.server.ca.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.AuthMethodFilter;

/**
 * Authentication method filter for the Dashboard REST API.
 *
 * This filter ensures users are properly authenticated before
 * accessing dashboard endpoints. Supports multiple authentication
 * methods:
 *
 * - Client Certificate (mutual TLS)
 * - Username/Password (LDAP)
 * - External SSO (via reverse proxy headers)
 *
 * Auth Method Configuration (auth-method.properties):
 *   dashboard = certUserDBAuthMgr,passwdUserDBAuthMgr
 */
@WebFilter(servletNames = "caDashboard")
public class DashboardAuthMethod extends AuthMethodFilter {

    private static final long serialVersionUID = 1L;
}
