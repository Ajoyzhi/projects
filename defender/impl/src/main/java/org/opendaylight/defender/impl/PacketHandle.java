/*
 * Copyright © 2017 no and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
/*
 * 监测模块
 * 接收packetin消息的notification，并注册notification，将超过阈值的packetin消息发送给处理模块。
 * 将超过阈值的packetin消息存储在datastore中
 */
package org.opendaylight.defender.impl;

import java.io.PrintWriter;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

import org.opendaylight.controller.md.sal.binding.api.DataBroker;
import org.opendaylight.controller.md.sal.binding.api.NotificationPublishService;
import org.opendaylight.yang.gen.v1.urn.opendaylight.defenderplugin.rev190812.LowWaterMarkBreachedBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.NodeConnectorId;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.NodeConnectorRef;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.NodeId;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.service.rev130709.PacketProcessingListener;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.service.rev130709.PacketReceived;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PacketHandle implements PacketProcessingListener {
	static Integer counter1 = 0;
	private DataBroker dataBroker;
	private NotificationPublishService notificationPublishService;
	public PacketHandle(DataBroker dataBroker, NotificationPublishService notificationPublishService) {
		this.dataBroker = dataBroker;
		this.notificationPublishService = notificationPublishService;
	}
	
	//to get the average packetin rate,so we need time and the number of packetin.
	// packet in 计数器和packet in的大小
    int counter = 0, packetSize;
	// 平均Packet in速率
    float avgPacketInRate;
    // Calendar 实例 get time
 	Calendar calendar = Calendar.getInstance();
 	// 开始时间
 	Long oldTime = calendar.getTimeInMillis();
 	// 截止时间和时间差
 	Long newTime, timeDiff;
    // 低阈值
 	int lowWaterMark = 1000;
    // 达到1000个数据包，就计算一次速率
 	int samplesLwm = 1000;
    int samplesHwm = 2000;
    
    //receive notification,that is,the packetin rate is higher than the markbench,then resolve the content of the notification.
 	// the content is the same as the yang.
 	// 源目的IP和MAC地址还有IP协议 notification
 	String srcIP, dstIP, ipProtocol, srcMac, dstMac;
 	// Ethernet类型
 	String stringEthType;
 	// TCP UDP 源目的端口号
 	Integer srcPort, dstPort;
 	
 	//if the rate is higher than markbench,the packetin will be stored in the datastore in the form of container LWM defined 
 	//in the yang
    // Reference to OpenFlow Plugin Yang DataStore
 	NodeConnectorRef ingressNodeConnectorRef;
 	// Ingress Switch Id
 	NodeId ingressNodeId;
 	// Ingress Switch Port Id from DataStore
 	NodeConnectorId ingressNodeConnectorId;
 	// Ingress Switch Port and Switch
 	String ingressConnector, ingressNode;
 	//the data resolved from the notification is the byte[]
 	byte[] payload, srcMacRaw, dstMacRaw, srcIPRaw, dstIPRaw, rawIPProtocol, rawEthType, rawSrcPort, rawDstPort;
 	
 	// 时间在datastore中的存储格式
 	DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    // 可能的攻击开始的时间和结束的时间
 	String upwardTime, downwardTime;
 	// calendar.getTimeInMillis()
 	Long upTime, downTime;
	// 是否到达警戒线
	Boolean lwmBreach = false;
	// 是否发送了警告消息
	Boolean notificationSent = false;
	// 已经存储的警告的key值
	List<String> dataBaseKeyList = new ArrayList<String>();
	
	// 向datastore中存储警告消息的类
	DefenderStore DefenderStore = new DefenderStore(dataBroker);
	
	private static final Logger LOG = (Logger) LoggerFactory.getLogger(PacketHandle.class);

	PrintWriter restoreNo;

	public DataBroker getdataBroker() {
		return dataBroker;
	}

	public void setdataBroker(DataBroker dataBroker) {
		this.dataBroker = dataBroker;
	}

	public void init() {
		LOG.info("PacketHandler init");
	}

	public void close() {
		LOG.info("PacketHandler close");
	}

	public void setNotificationPublishService(NotificationPublishService notificationPublishService) {
		this.notificationPublishService = notificationPublishService;
	}

	public NotificationPublishService getNotificationPublishService(
			NotificationPublishService notificationPublishService) {
		return this.notificationPublishService;
	}
    
	public void LWM() {
		LOG.debug("The low mark brench is " + lowWaterMark);//1000
		counter = counter +1;
		// 计算平均packet in速率
	    // 收到samplesLwm=1000个数据包以后 计算收到相同数量的数据包的时间
		if ((counter % samplesLwm) == 0) {
			// 获取calendar实例
			calendar = Calendar.getInstance();
			// 获取当前时间,毫秒单位
			newTime = calendar.getTimeInMillis();
			// 计算时间差
			timeDiff = newTime - oldTime;
			// 将oldTime时间更新
			oldTime = newTime;
			// 收到个数据包的平均速率，单位包/秒
			avgPacketInRate = (samplesLwm / timeDiff) * 1000;
			counter = 0;
			LOG.info("Average PacketIn Rate is " + avgPacketInRate);
		}
		
		// 如果平均包速率比lowWaterMark值大,即有可能发生攻击
		if (avgPacketInRate > lowWaterMark) {
			// lwmBreach的初始值是false ，说明第一次超过警戒线，防止重复发送notification
			if (lwmBreach.equals(false)) {
				// 将发送的数据设置为以下对应值   将超过阈值的数据包全部发送给处理模块
				LowWaterMarkBreachedBuilder lowWaterMarkBreachedBuilder = new LowWaterMarkBreachedBuilder();
				lowWaterMarkBreachedBuilder.setSrcPort(srcPort);
				lowWaterMarkBreachedBuilder.setDstPort(dstPort);
				lowWaterMarkBreachedBuilder.setSrcIP(srcIP);
				lowWaterMarkBreachedBuilder.setDstIP(dstIP);
				lowWaterMarkBreachedBuilder.setProtocol(ipProtocol);
				lowWaterMarkBreachedBuilder.setSrcMac(srcMac);
				lowWaterMarkBreachedBuilder.setDstMac(dstMac);
				LOG.debug("Put Notification");
				try {
					// 注册发送服务
					notificationPublishService.putNotification(lowWaterMarkBreachedBuilder.build());
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
			}
			// 已经达到警戒线，并已经发出通知
			lwmBreach = true;
			// 设置dataBroker
			DefenderStore.setdataBroker(dataBroker);
			calendar = Calendar.getInstance();
	    	// 初始值设置为0，还不确定什么时候会降到警戒线以下				
			downwardTime = "0";

			// 存到数据datastore中
			// 先设置key，用交换机和端口以及srcIP构成key
			String databaseKey = ingressNode + "-" + srcMac;
			// 避免重复存储
			if (!(dataBaseKeyList.contains(databaseKey))) {
				// 如果没有包含这个key就存到datastore中
     			dataBaseKeyList.add(databaseKey);
				upTime = calendar.getTimeInMillis();
				upwardTime = dateFormat.format(upTime);
				DefenderStore.addData(databaseKey, ingressNode, ingressConnector, srcIP, dstIP,srcMac,dstMac, ipProtocol, srcPort,
									dstPort, packetSize, upwardTime, downwardTime);			
				}
		}				
		// 平均包速率比lowWaterMark小，并且之前达到了lowWaterMark，说明现在速率已经降下来了
		else if (lwmBreach) {
			// 低于警戒线
			lwmBreach = false;
			// 将低于lwmWaterMark的时间记录到数据库中
			for (String dbKey : dataBaseKeyList) {
				downTime = calendar.getTimeInMillis();
				// 重新设置downwardTime的值，即在这个时刻降到了警戒线以下
				downwardTime = dateFormat.format(downTime);
				// 将downtime添加到datastore中
				DefenderStore.addDownTime(dbKey, downwardTime);
			}
		}
	}
	@Override
	/*
	 * 注册packetin  notification 的接收：
	 * provider.java中 notificationServices.registerNotificationListener(new PacketHandle())
	 * 在impl-blueprint.xml中注册
	 */
	public void onPacketReceived(PacketReceived notification) {
		// 解析数据包 是解析packetin数据包的头部么？？
		ingressNodeConnectorRef = notification.getIngress();
		ingressNodeConnectorId = InventoryUtility.getNodeConnectorId(ingressNodeConnectorRef);
		ingressConnector = ingressNodeConnectorId.getValue();
		ingressNodeId = InventoryUtility.getNodeId(ingressNodeConnectorRef);
		ingressNode = ingressNodeId.getValue();

		// 从notification获取payload  payload为数据部分，不包括头部
		payload = notification.getPayload();
		// 获取payload的大小
		packetSize = payload.length;
		// 解析MAC地址
		srcMacRaw = PacketParsing.extractSrcMac(payload);
		dstMacRaw = PacketParsing.extractDstMac(payload);
		srcMac = PacketParsing.rawMacToString(srcMacRaw);
		dstMac = PacketParsing.rawMacToString(dstMacRaw);
		// 解析Ethernet类型
		rawEthType = PacketParsing.extractEtherType(payload);
		stringEthType = PacketParsing.rawEthTypeToString(rawEthType);
		// 解析IP地址
		dstIPRaw = PacketParsing.extractDstIP(payload);
		srcIPRaw = PacketParsing.extractSrcIP(payload);
		dstIP = PacketParsing.rawIPToString(dstIPRaw);
		srcIP = PacketParsing.rawIPToString(srcIPRaw);
		// 解析IP协议
		rawIPProtocol = PacketParsing.extractIPProtocol(payload);
		ipProtocol = PacketParsing.rawIPProtoToString(rawIPProtocol).toString();
		// 解析端口
		rawSrcPort = PacketParsing.extractSrcPort(payload);
		srcPort = PacketParsing.rawPortToInteger(rawSrcPort);
		rawDstPort = PacketParsing.extractDstPort(payload);
		dstPort = PacketParsing.rawPortToInteger(rawDstPort);
		
		LWM();
	}

}
