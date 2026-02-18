//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.rest.base;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.system.Feature;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.ConfigStore;

/**
 * @author Endi S. Dewata
 */
public class FeatureServletBase {
    public static final Logger logger = LoggerFactory.getLogger(FeatureServletBase.class);

    private CMSEngine engine;

    public FeatureServletBase(CMSEngine engine) {
        this.engine = engine;
    }

    public List<Feature> listFeatures() {
        EngineConfig config = engine.getConfig();
        ConfigStore cs = config.getSubStore("features", ConfigStore.class);
        List<Feature> features = new ArrayList<>();
        Enumeration<String> tags = cs.getSubStoreNames().elements();
        while (tags.hasMoreElements()) {
            String tag = tags.nextElement();
            features.add(createFeature(cs, tag));
        }
        return features;
    }

    public Feature getFeature(String featureId) {
        EngineConfig config = engine.getConfig();
        ConfigStore cs = config.getSubStore("features", ConfigStore.class);
        Enumeration<String> tags = cs.getSubStoreNames().elements();
        while (tags.hasMoreElements()) {
            String tag = tags.nextElement();
            if (tag.equals(featureId)) {
                return createFeature(cs, tag);
            }
        }
        throw new ResourceNotFoundException("Feature " + featureId + " not supported");
    }

    private Feature createFeature(ConfigStore cs, String tag) {
        Map<String, String> props = cs.getSubStore(tag).getProperties();
        Feature feature = new Feature();
        feature.setId(tag);
        feature.setEnabled(Boolean.parseBoolean(props.get("enabled")));
        feature.setDescription(props.get("description"));
        feature.setVersion(props.get("version"));
        return feature;
    }
}
