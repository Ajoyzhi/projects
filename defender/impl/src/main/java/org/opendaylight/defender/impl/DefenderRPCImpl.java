/*
 * Copyright © 2017 no and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
/*
 * 用户模块
 * 利用RPC查看攻击情况
 */
package org.opendaylight.defender.impl;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import org.opendaylight.controller.md.sal.binding.api.DataBroker;
import org.opendaylight.controller.md.sal.binding.api.ReadOnlyTransaction;
import org.opendaylight.controller.md.sal.common.api.data.LogicalDatastoreType;
import org.opendaylight.yang.gen.v1.urn.opendaylight.defenderplugin.rev190812.AttacksFromIPInput;
import org.opendaylight.yang.gen.v1.urn.opendaylight.defenderplugin.rev190812.AttacksFromIPOutput;
import org.opendaylight.yang.gen.v1.urn.opendaylight.defenderplugin.rev190812.AttacksFromIPOutputBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.defenderplugin.rev190812.AttacksInTimeInput;
import org.opendaylight.yang.gen.v1.urn.opendaylight.defenderplugin.rev190812.AttacksInTimeOutput;
import org.opendaylight.yang.gen.v1.urn.opendaylight.defenderplugin.rev190812.AttacksInTimeOutputBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.defenderplugin.rev190812.AttacksToIPInput;
import org.opendaylight.yang.gen.v1.urn.opendaylight.defenderplugin.rev190812.AttacksToIPOutput;
import org.opendaylight.yang.gen.v1.urn.opendaylight.defenderplugin.rev190812.AttacksToIPOutputBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.defenderplugin.rev190812.DefenderpluginService;
import org.opendaylight.yang.gen.v1.urn.opendaylight.defenderplugin.rev190812.LWM;
import org.opendaylight.yang.gen.v1.urn.opendaylight.defenderplugin.rev190812.alert.Alerts;
import org.opendaylight.yang.gen.v1.urn.opendaylight.defenderplugin.rev190812.alert.AlertsBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.defenderplugin.rev190812.lwm.Lowwatermark;
import org.opendaylight.yangtools.yang.binding.InstanceIdentifier;
import org.opendaylight.yangtools.yang.common.RpcResult;
import org.opendaylight.yangtools.yang.common.RpcResultBuilder;

import com.google.common.base.Optional;

public class DefenderRPCImpl implements DefenderpluginService{
	private DataBroker dataBroker;
	
	public DefenderRPCImpl (DataBroker dataBroker) {
		this.dataBroker = dataBroker;
	}
	public DataBroker getDataBroker() {
		return dataBroker;
	}
	
	public void setDataBroker(DataBroker dataBroker) {
		this.dataBroker = dataBroker;
	}
	/**
	 * 根据目的IP地址来查找被攻击的记录
	 */
	@Override
	public Future<RpcResult<AttacksToIPOutput>> attacksToIP(AttacksToIPInput input) {
		String dstIP = input.getDstIP();
		ReadOnlyTransaction readOnly = dataBroker.newReadOnlyTransaction();
		// 从该路径下获取所有攻击记录然后根据条件筛选返回
		InstanceIdentifier<LWM> instanceIdentifier = InstanceIdentifier.builder(LWM.class).build();
		Optional<LWM> results = null;
		try {
			results = readOnly.read(LogicalDatastoreType.OPERATIONAL, instanceIdentifier).get();
		} catch (InterruptedException | ExecutionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		LWM lwm = null;
		if (results.isPresent()) {
			lwm = results.get();
		}
		List<Lowwatermark> resultList = lwm.getLowwatermark();
		List<Alerts> alerts = new ArrayList<>();
		AlertsBuilder builder = new AlertsBuilder();
		for (Lowwatermark low : resultList) {
			if (low.getDstIP().equals(dstIP)) {
				builder.setDowntime(low.getDownwardTime());
				builder.setUptime(low.getUpwardTime());
				builder.setDstIP(low.getDstIP());
				builder.setSrcIP(low.getSrcIP());
				builder.setDstMAC(low.getDstMAC());
				builder.setSrcMAC(low.getSrcMAC());
				builder.setDstPort(low.getDstPort());
				builder.setSrcPort(low.getSrcPort());
				builder.setProtocol(low.getProtocol());
				alerts.add(builder.build());
			}
		}
		AttacksToIPOutputBuilder outputBuilder = new AttacksToIPOutputBuilder();
		outputBuilder.setAlerts(alerts);
		return RpcResultBuilder.success(outputBuilder.build()).buildFuture();
	}
	/**
	 * 根据时间来查找发动攻击的记录
	 */
	@Override
	public Future<RpcResult<AttacksInTimeOutput>> attacksInTime(AttacksInTimeInput input) {
		DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		String fromTime = input.getFromTime();
		String endTime = input.getEndTime();
		ReadOnlyTransaction readOnly = dataBroker.newReadOnlyTransaction();
		// 从该路径下获取所有攻击记录然后根据条件筛选返回
		InstanceIdentifier<LWM> instanceIdentifier = InstanceIdentifier.builder(LWM.class).build();
		Optional<LWM> results = null;
		try {
			results = readOnly.read(LogicalDatastoreType.OPERATIONAL, instanceIdentifier).get();
		} catch (InterruptedException | ExecutionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		LWM lwm = null;
		if (results.isPresent()) {
			lwm = results.get();
		}
		List<Lowwatermark> resultList = lwm.getLowwatermark();
		List<Alerts> alerts = new ArrayList<>();
		AlertsBuilder builder = new AlertsBuilder();
		for (Lowwatermark low : resultList) {
           // 将涉及到的时间均转化为yyyy-MM-dd HH-mm-ss的形式，便于比较
           // 只获取上传时间，上传时间在输入的时间段内均算此时的攻击
			String timeString = low.getUpwardTime();
			Date from = null;
			try {
				from = dateFormat.parse(fromTime);
			} catch (ParseException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			Date end = null;
			try {
				end = dateFormat.parse(endTime);
			} catch (ParseException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			Date time = null;
			try {
				time = dateFormat.parse(timeString);
			} catch (ParseException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			if (from.getTime() < time.getTime() && time.getTime() < end.getTime()) {
				builder.setDowntime(low.getDownwardTime());
				builder.setUptime(low.getUpwardTime());
				builder.setDstIP(low.getDstIP());
				builder.setSrcIP(low.getSrcIP());
				builder.setDstMAC(low.getDstMAC());
				builder.setSrcMAC(low.getSrcMAC());
				builder.setDstPort(low.getDstPort());
				builder.setSrcPort(low.getSrcPort());
				builder.setProtocol(low.getProtocol());
				alerts.add(builder.build());
			}
		}
		AttacksInTimeOutputBuilder outputBuilder = new AttacksInTimeOutputBuilder();
		outputBuilder.setAlerts(alerts);
		return RpcResultBuilder.success(outputBuilder.build()).buildFuture();
	}
	/**
	 * 根据源IP地址来返回攻击记录
	 */
	@Override
	public Future<RpcResult<AttacksFromIPOutput>> attacksFromIP(AttacksFromIPInput input) {
		// 从输入中获取源IP地址
		String srcIP = input.getSrcIP();
		// 用DataBroker建立只读事务
		ReadOnlyTransaction readOnly = dataBroker.newReadOnlyTransaction();
		// 从该路径下获取所有攻击记录然后根据条件筛选返回
		InstanceIdentifier<LWM> instanceIdentifier = InstanceIdentifier.builder(LWM.class).build();
		Optional<LWM> results = null;
		try {
			results = readOnly.read(LogicalDatastoreType.OPERATIONAL, instanceIdentifier).get();
		} catch (InterruptedException | ExecutionException e) {
			e.printStackTrace();
		}
		LWM lwm = null;
		if (results.isPresent()) {
			lwm = results.get();
		}
		List<Lowwatermark> resultList = lwm.getLowwatermark();
		List<Alerts> alerts = new ArrayList<>();
		AlertsBuilder builder = new AlertsBuilder();
		// 遍历从数据库中读取的每一项记录
		for (Lowwatermark low : resultList) {
			// 按照源IP地址进行筛选
			if (low.getSrcIP().equals(srcIP)) {
				builder.setDowntime(low.getDownwardTime());
				builder.setUptime(low.getUpwardTime());
				builder.setDstIP(low.getDstIP());
				builder.setSrcIP(low.getSrcIP());
				builder.setDstMAC(low.getDstMAC());
				builder.setSrcMAC(low.getSrcMAC());
				builder.setDstPort(low.getDstPort());
				builder.setSrcPort(low.getSrcPort());
				builder.setProtocol(low.getProtocol());
				alerts.add(builder.build());
			}
		}
		// 创建Output的builder类并将相关记录赋值
		AttacksFromIPOutputBuilder outputBuilder = new AttacksFromIPOutputBuilder();
		outputBuilder.setAlerts(alerts);
		// 最后用RpcResultBuilder构建Future来返回
		return RpcResultBuilder.success(outputBuilder.build()).buildFuture();
	}
}
