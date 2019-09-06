/*
 * Copyright © 2017 no and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

package org.opendaylight.defender.impl;

import java.util.ArrayList;
import java.util.List;

import org.opendaylight.controller.md.sal.binding.api.DataBroker;
import org.opendaylight.controller.md.sal.binding.api.WriteTransaction;
import org.opendaylight.controller.md.sal.common.api.data.LogicalDatastoreType;
import org.opendaylight.yang.gen.v1.urn.opendaylight.defenderplugin.rev190812.LWM;
import org.opendaylight.yang.gen.v1.urn.opendaylight.defenderplugin.rev190812.LWMBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.defenderplugin.rev190812.lwm.Lowwatermark;
import org.opendaylight.yang.gen.v1.urn.opendaylight.defenderplugin.rev190812.lwm.LowwatermarkBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.defenderplugin.rev190812.lwm.LowwatermarkKey;
import org.opendaylight.yangtools.yang.binding.InstanceIdentifier;

public class DefenderStore {
	//创建传递参数的私有DataBroker成员
	private DataBroker dataBroker;
	
	public void setdataBroker(DataBroker dataBroker) {
		this.dataBroker = dataBroker;
	}
	
	public DefenderStore(DataBroker dataBroker) {
		this.dataBroker = dataBroker;
	}
	// 设置往datastore中存储的根路径，即在container LWM中创建一个唯一的路径标识。
	InstanceIdentifier<LWM> instanceIdentifier = InstanceIdentifier.builder(LWM.class).build();
	// yang文件中，container中的list lowwatermark对应的java类
	List<Lowwatermark> lwmList = new ArrayList<>();
	LWMBuilder lwmBuilder = new LWMBuilder();
	
	public void addData(String secKey, String nodeId, String nodeConnectorId, String srcIP, String dstIP,String srcMAC, String dstMAC,
			String protocol, int srcPort, int dstPort, int packetSize, String uptime, String downtime) {
		//list lowwatermark对应的builder函数
		LowwatermarkBuilder lowwatermarkBuilder = new LowwatermarkBuilder();
		// key值是ingressNode + "-" + srcMac
		lowwatermarkBuilder.setSecKey(secKey);
		lowwatermarkBuilder.setNodeID(nodeId);
		//lowwatermarkBuilder.setNodeConnectorID(nodeConnectorId);
		lowwatermarkBuilder.setSrcMAC(srcMAC);
		lowwatermarkBuilder.setDstMAC(dstMAC);
		lowwatermarkBuilder.setSrcIP(srcIP);
		lowwatermarkBuilder.setDstIP(dstIP);
		lowwatermarkBuilder.setProtocol(protocol);
		lowwatermarkBuilder.setSrcPort(srcPort);
		lowwatermarkBuilder.setDstPort(dstPort);
		lowwatermarkBuilder.setPacketSize(packetSize);
		lowwatermarkBuilder.setUpwardTime(uptime);
		lowwatermarkBuilder.setDownwardTime(downtime);
		Lowwatermark lwm = lowwatermarkBuilder.build();
		// 先向list中添加
		lwmList.add(lwm);
		// 将list赋值给LWM
		lwmBuilder.setLowwatermark(lwmList);
		LWM lwm2 = lwmBuilder.build();
		//创建对datastore的写事务
		WriteTransaction writeTransaction = dataBroker.newWriteOnlyTransaction();
		// 用merge操作来向根节点下添加子节点
		writeTransaction.merge(LogicalDatastoreType.OPERATIONAL, instanceIdentifier, lwm2);
		writeTransaction.submit();
	}
	
	public void addDownTime(String secKey,String downtime) {
		// 用ingressNode + "-" + srcMac 创建一个LowwatermarkKey
		LowwatermarkKey seclwmKey = new LowwatermarkKey(secKey);
		// 从LWM的子节点LowwatermarkKey下寻找相应的记录
		InstanceIdentifier<Lowwatermark> secLwmIdentifier = InstanceIdentifier.builder(LWM.class).child(Lowwatermark.class, seclwmKey).build();
		LowwatermarkBuilder lowwatermarkBuilder = new LowwatermarkBuilder();
		lowwatermarkBuilder.setSecKey(secKey);
		lowwatermarkBuilder.setDownwardTime(downtime);
		Lowwatermark lowwatermark = lowwatermarkBuilder.build();
		lwmList.add(lowwatermark);
		WriteTransaction writeTransaction = dataBroker.newWriteOnlyTransaction();
		// 用merge操作来更新downtime
		writeTransaction.merge(LogicalDatastoreType.OPERATIONAL, secLwmIdentifier, lowwatermark);
		writeTransaction.submit();
	}
}
