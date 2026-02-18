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

import org.dogtagpki.server.rest.v2.filters.ACLFilter;

/**
 * ACL filter for the Dashboard REST API.
 *
 * This filter enforces that users can only access their own dashboard data.
 * The dashboard endpoints are designed for end-entity users to view their
 * own certificates and requests.
 *
 * Access Control:
 * - All authenticated users can access the dashboard
 * - Each endpoint returns only data owned by the current user
 * - No cross-user data access is permitted
 *
 * ACL Configuration (acl.properties):
 *   dashboard = certServer.ee.dashboard,read
 */
@WebFilter(servletNames = "caDashboard")
public class DashboardACL extends ACLFilter {

    private static final long serialVersionUID = 1L;

    private static final String ACL_NAME = "dashboard";

    @Override
    protected String getACLName(String method, String path) {
        // All dashboard endpoints use the same ACL
        // The endpoint implementation enforces user-based filtering
        return ACL_NAME;
    }
}
