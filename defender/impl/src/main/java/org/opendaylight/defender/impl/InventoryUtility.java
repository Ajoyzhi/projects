/*
 * Copyright © 2017 no and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

package org.opendaylight.defender.impl;

import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.*;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.node.NodeConnector;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.node.NodeConnectorKey;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.nodes.NodeKey;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.nodes.Node;

public class InventoryUtility {
	
	private InventoryUtility() {
		
	}
	
	public static final String OPENFLOW_NODE_PREFIX = "openflow:";
	
	public static NodeId getNodeId(NodeConnectorRef nodeConnectorRef) {
		return nodeConnectorRef.getValue().firstKeyOf(Node.class, NodeKey.class).getId();
	}
	

	public static NodeConnectorId getNodeConnectorId(NodeConnectorRef nodeConnectorRef) {
		return nodeConnectorRef.getValue().firstKeyOf(NodeConnector.class , NodeConnectorKey.class).getId();
	}
}
