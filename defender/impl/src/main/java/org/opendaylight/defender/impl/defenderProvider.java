/*
 * Copyright © 2017 no and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
package org.opendaylight.defender.impl;

import org.opendaylight.controller.md.sal.binding.api.DataBroker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class defenderProvider {

    private static final Logger LOG = LoggerFactory.getLogger(defenderProvider.class);

    private final DataBroker dataBroker;

    public defenderProvider(final DataBroker dataBroker) {
        this.dataBroker = dataBroker;
    }

    /**
     * Method called when the blueprint container is created.
     */
    public void init() {
        LOG.info("defenderProvider Session Initiated");
    }

    /**
     * Method called when the blueprint container is destroyed.
     */
    public void close() {
        LOG.info("defenderProvider Closed");
    }
}