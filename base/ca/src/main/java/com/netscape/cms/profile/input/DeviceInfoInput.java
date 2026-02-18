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
package com.netscape.cms.profile.input;

import java.util.Locale;
import java.util.Map;

import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.cms.profile.common.Profile;
import com.netscape.cms.profile.common.ProfileInputConfig;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.request.Request;

/**
 * This class implements a device information input that collects
 * device metadata for certificate enrollment. The device information
 * is stored in the certificate request and can be used for webhook
 * notifications and certificate lifecycle management.
 *
 * Supported device types:
 * - server: Traditional server certificates
 * - iot: Internet of Things devices
 * - mobile: Mobile devices (phones, tablets)
 * - workstation: Desktop/laptop workstations
 * - network: Network equipment (routers, switches)
 * - container: Container/Kubernetes workloads
 * - service: Service accounts/applications
 * - other: Other device types
 *
 * Configuration in profile:
 *   input.i1.class_id=deviceInfoInputImpl
 *
 * @version $Revision$, $Date$
 */
public class DeviceInfoInput extends EnrollInput {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(DeviceInfoInput.class);

    // Input field names
    public static final String DEVICE_TYPE = "deviceType";
    public static final String DEVICE_ID = "deviceId";
    public static final String DEVICE_GROUP = "deviceGroup";
    public static final String DEVICE_ENVIRONMENT = "deviceEnvironment";
    public static final String DEVICE_LOCATION = "deviceLocation";
    public static final String DEVICE_OWNER = "deviceOwner";

    // Predefined device types
    public static final String TYPE_SERVER = "server";
    public static final String TYPE_IOT = "iot";
    public static final String TYPE_MOBILE = "mobile";
    public static final String TYPE_WORKSTATION = "workstation";
    public static final String TYPE_NETWORK = "network";
    public static final String TYPE_CONTAINER = "container";
    public static final String TYPE_SERVICE = "service";
    public static final String TYPE_OTHER = "other";

    // Device type choices for dropdown
    public static final String DEVICE_TYPE_CHOICES =
            TYPE_SERVER + "," +
            TYPE_IOT + "," +
            TYPE_MOBILE + "," +
            TYPE_WORKSTATION + "," +
            TYPE_NETWORK + "," +
            TYPE_CONTAINER + "," +
            TYPE_SERVICE + "," +
            TYPE_OTHER;

    // Environment choices
    public static final String ENV_PRODUCTION = "production";
    public static final String ENV_STAGING = "staging";
    public static final String ENV_DEVELOPMENT = "development";
    public static final String ENV_TEST = "test";

    public static final String ENVIRONMENT_CHOICES =
            ENV_PRODUCTION + "," +
            ENV_STAGING + "," +
            ENV_DEVELOPMENT + "," +
            ENV_TEST;

    public DeviceInfoInput() {
        addValueName(DEVICE_TYPE);
        addValueName(DEVICE_ID);
        addValueName(DEVICE_GROUP);
        addValueName(DEVICE_ENVIRONMENT);
        addValueName(DEVICE_LOCATION);
        addValueName(DEVICE_OWNER);
    }

    /**
     * Initializes this input plugin.
     */
    @Override
    public void init(Profile profile, ProfileInputConfig config) throws EProfileException {
        super.init(profile, config);
        logger.debug("DeviceInfoInput: initialized");
    }

    /**
     * Retrieves the localizable name of this input.
     */
    @Override
    public String getName(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_INPUT_DEVICE_INFO_NAME");
    }

    /**
     * Retrieves the localizable description of this input.
     */
    @Override
    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_INPUT_DEVICE_INFO_TEXT");
    }

    /**
     * Populates the request with device information from the enrollment form.
     * This data will be stored in the certificate request and can be accessed
     * by listeners (like WebhookListener) for notification routing.
     */
    @Override
    public void populate(Map<String, String> ctx, Request request) throws Exception {
        String deviceType = ctx.get(DEVICE_TYPE);
        String deviceId = ctx.get(DEVICE_ID);
        String deviceGroup = ctx.get(DEVICE_GROUP);
        String deviceEnvironment = ctx.get(DEVICE_ENVIRONMENT);
        String deviceLocation = ctx.get(DEVICE_LOCATION);
        String deviceOwner = ctx.get(DEVICE_OWNER);

        logger.debug("DeviceInfoInput: populate - deviceType=" + deviceType +
                " deviceId=" + deviceId +
                " deviceGroup=" + deviceGroup);

        // Store in request extension data for access by listeners
        if (deviceType != null && !deviceType.isEmpty()) {
            request.setExtData(DEVICE_TYPE, deviceType);
        }
        if (deviceId != null && !deviceId.isEmpty()) {
            request.setExtData(DEVICE_ID, deviceId);
        }
        if (deviceGroup != null && !deviceGroup.isEmpty()) {
            request.setExtData(DEVICE_GROUP, deviceGroup);
        }
        if (deviceEnvironment != null && !deviceEnvironment.isEmpty()) {
            request.setExtData(DEVICE_ENVIRONMENT, deviceEnvironment);
        }
        if (deviceLocation != null && !deviceLocation.isEmpty()) {
            request.setExtData(DEVICE_LOCATION, deviceLocation);
        }
        if (deviceOwner != null && !deviceOwner.isEmpty()) {
            request.setExtData(DEVICE_OWNER, deviceOwner);
        }
    }

    /**
     * Retrieves the descriptor of the given value parameter by name.
     * This defines how each field is rendered in the enrollment form.
     */
    @Override
    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(DEVICE_TYPE)) {
            return new Descriptor(
                    IDescriptor.CHOICE,
                    DEVICE_TYPE_CHOICES,
                    TYPE_SERVER,
                    CMS.getUserMessage(locale, "CMS_PROFILE_DEVICE_TYPE"));
        } else if (name.equals(DEVICE_ID)) {
            return new Descriptor(
                    IDescriptor.STRING,
                    null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_DEVICE_ID"));
        } else if (name.equals(DEVICE_GROUP)) {
            return new Descriptor(
                    IDescriptor.STRING,
                    null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_DEVICE_GROUP"));
        } else if (name.equals(DEVICE_ENVIRONMENT)) {
            return new Descriptor(
                    IDescriptor.CHOICE,
                    ENVIRONMENT_CHOICES,
                    ENV_PRODUCTION,
                    CMS.getUserMessage(locale, "CMS_PROFILE_DEVICE_ENVIRONMENT"));
        } else if (name.equals(DEVICE_LOCATION)) {
            return new Descriptor(
                    IDescriptor.STRING,
                    null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_DEVICE_LOCATION"));
        } else if (name.equals(DEVICE_OWNER)) {
            return new Descriptor(
                    IDescriptor.STRING,
                    null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_DEVICE_OWNER"));
        }
        return null;
    }
}
