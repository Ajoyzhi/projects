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
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import org.opendaylight.controller.md.sal.binding.api.DataBroker;
import org.opendaylight.controller.md.sal.binding.api.ReadOnlyTransaction;
import org.opendaylight.controller.md.sal.common.api.data.LogicalDatastoreType;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.inventory.rev130819.tables.table.Flow;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.inventory.rev130819.tables.table.FlowBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.inventory.rev130819.tables.table.FlowKey;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.service.rev130819.AddFlowInputBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.service.rev130819.AddFlowOutput;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.service.rev130819.FlowTableRef;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.service.rev130819.SalFlowService;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.types.rev131026.FlowRef;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.types.rev131026.flow.InstructionsBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.types.rev131026.flow.MatchBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.types.rev131026.instruction.list.Instruction;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.types.rev131026.instruction.instruction.ApplyActionsCaseBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.types.rev131026.instruction.instruction.apply.actions._case.ApplyActionsBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.types.rev131026.instruction.list.InstructionBuilder;
import org.opendaylight.yang.gen.v1.urn.ietf.params.xml.ns.yang.ietf.inet.types.rev130715.Uri;
import org.opendaylight.yang.gen.v1.urn.ietf.params.xml.ns.yang.ietf.yang.types.rev130715.MacAddress;
import org.opendaylight.yang.gen.v1.urn.opendaylight.action.types.rev131112.action.action.DropActionCaseBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.action.types.rev131112.action.action.drop.action._case.DropActionBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.action.types.rev131112.action.list.ActionBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.defenderplugin.rev190812.DefenderpluginListener;
import org.opendaylight.yang.gen.v1.urn.opendaylight.defenderplugin.rev190812.LowWaterMarkBreached;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.inventory.rev130819.FlowCapableNode;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.inventory.rev130819.FlowId;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.inventory.rev130819.tables.Table;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.inventory.rev130819.tables.TableKey;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.NodeRef;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.Nodes;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.nodes.Node;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.nodes.NodeKey;
import org.opendaylight.yang.gen.v1.urn.opendaylight.model.match.types.rev131026.ethernet.match.fields.EthernetDestinationBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.model.match.types.rev131026.ethernet.match.fields.EthernetSourceBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.model.match.types.rev131026.match.EthernetMatchBuilder;
import org.opendaylight.yangtools.yang.binding.InstanceIdentifier;
import org.opendaylight.yangtools.yang.common.RpcResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.base.Optional;

/*
 * 处理模块
 * 接收notification消息，并根据notification中的srcMAC和dstMAC下发流表
 * (1) 解析notification中的源MAC和目的MAC，作为流规则的匹配域
 * （2）遍历datastore中存储的nodes，即交换机，在所有交换机的table 0 中下发流规则-》对datastore中的数据进行写操作
*/
//接收notification，即实现module明+Listener
public class HandlerModule implements DefenderpluginListener {
	Logger LOG = LoggerFactory.getLogger(HandlerModule.class);
	public static final String FLOW_ID_PREFIX = "USEC-";
	// 创建流编号
    public static int flowNo = 0;
	private DataBroker dataBroker;
	private SalFlowService salFlowService;
	
	public HandlerModule(DataBroker dataBroker,SalFlowService salFlowService) {
		this.dataBroker = dataBroker;
		this.salFlowService = salFlowService;
	}
	// 接收监测模块超过阈值的数据包，并针对该类数据包的目的mac下发流表
	@Override
	public void onLowWaterMarkBreached(LowWaterMarkBreached notification) {
		// 从databroker获取全部的节点,即所有的交换机及其端口？
		List<Node> nodes = getAllNodes(dataBroker);
		String dstMAC = notification.getDstMac();
		// 如果不是ARP请求
		if(!dstMAC.equals("FF:FF:FF:FF:FF:FF")) {
		// 如果是APR请求的话，则不按照这个目的地址添加drop流表，防止误杀
		// 遍历每一个节点，对每一个节点下发流表
		// 根据接收的消息创建一个flow
			Flow flow = createProhibiteFlow(notification);
			for (Node node : nodes) {
				// 看Yang文件NodeKey的变量是NodeId
				NodeKey nodeKey = node.getKey();
				// 寻找Nodes根节点下的子节点，由NodeKey来寻找Nodes下的子节点
				InstanceIdentifier<Node> nodeId = InstanceIdentifier.builder(Nodes.class).child(Node.class, nodeKey)
						.build();
				// 对每个节点下发流表
				addProhibitFlow(nodeId, flow);
			}
		}		
	}

	private void addProhibitFlow(InstanceIdentifier<Node> nodeId, Flow flow) {
		// node 是遍历datastore中nodeids中的每一个nodeid
		LOG.info("Adding prohibit flows for node {} ", nodeId);
		// 根据nodeId获取tableId
		InstanceIdentifier<Table> tableId = getTableInstanceId(nodeId);
		// 创建一个FlowKey
		FlowKey flowKey = new FlowKey(new FlowId(FLOW_ID_PREFIX + String.valueOf(flowNo++)));
		// 在datastore中创建一个子路经
		InstanceIdentifier<Flow> flowId = tableId.child(Flow.class, flowKey);
		// 在这个子路经下添加一个流
		Future<RpcResult<AddFlowOutput>> result = writeFlow(nodeId, tableId, flowId, flow);
		AddFlowOutput output = null;
		try {
			output = result.get().getResult();
		} catch (InterruptedException | ExecutionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		LOG.info("Added prohibit flows for node {} ", nodeId);
	}
	private Future<RpcResult<AddFlowOutput>> writeFlow(InstanceIdentifier<Node> nodeId,
			InstanceIdentifier<Table> tableId, InstanceIdentifier<Flow> flowId, Flow flow) {
		// 创建一个AddflowInputBuilder
		AddFlowInputBuilder builder = new AddFlowInputBuilder(flow);
		// 指定一个节点
		builder.setNode(new NodeRef(nodeId));
		// flow的路径
		builder.setFlowRef(new FlowRef(flowId));
		// table的路径
		builder.setFlowTable(new FlowTableRef(tableId));
		builder.setTransactionUri(new Uri(flow.getId().getValue()));
		return salFlowService.addFlow(builder.build());
	}
	private InstanceIdentifier<Table> getTableInstanceId(InstanceIdentifier<Node> nodeId) {
		// get flow table key
		// 获取0号流表
		short tableId = 0;
		TableKey flowTableKey = new TableKey(tableId);
		return nodeId.augmentation(FlowCapableNode.class).child(Table.class,flowTableKey);
	}
	private Flow createProhibiteFlow(LowWaterMarkBreached notification) {
		String srcMAC = notification.getSrcMac();
		String dstMAC = notification.getDstMac();
		// 设置名字和tableID以及flowID
		FlowBuilder builder = new FlowBuilder();
        // 可以拆开写 
		//builder.setFlowName("prohibitFlow").setTableId(Short.valueOf("0"));
        builder.setFlowName("prohibitFlow").setTableId(Short.valueOf("0"));
		builder.setId(new FlowId(Long.toString(builder.hashCode())));
		// 设置匹配域
		MatchBuilder matchBuilder = new MatchBuilder();
		// 以太网的匹配  根据源/目的MAC地址找到受攻击和攻击主机
		EthernetMatchBuilder ethernetMatchBuilder = new EthernetMatchBuilder();
		// 以太网的源、目的地址
		EthernetDestinationBuilder ethernetDestinationBuilder = new EthernetDestinationBuilder();
		ethernetDestinationBuilder.setAddress(new MacAddress(dstMAC));
		ethernetMatchBuilder.setEthernetDestination(ethernetDestinationBuilder.build());
		EthernetSourceBuilder ethernetSourceBuilder = new EthernetSourceBuilder();
		ethernetSourceBuilder.setAddress(new MacAddress(srcMAC));
		ethernetMatchBuilder.setEthernetSource(ethernetSourceBuilder.build());
		matchBuilder.setEthernetMatch(ethernetMatchBuilder.build());
		// 设置匹配域
		builder.setMatch(matchBuilder.build());
		// 设置指令
		InstructionsBuilder instructionsBuilder = new InstructionsBuilder();
		InstructionBuilder instructionBuilder = new InstructionBuilder();
		ApplyActionsCaseBuilder actionsCaseBuilder = new ApplyActionsCaseBuilder();
        ApplyActionsBuilder actionsBuilder = new ApplyActionsBuilder();
		ActionBuilder actionBuilder = new ActionBuilder();
		actionBuilder.setAction(new DropActionCaseBuilder().setDropAction(new DropActionBuilder().build()).build());
		List<org.opendaylight.yang.gen.v1.urn.opendaylight.action.types.rev131112.action.list.Action> action = new ArrayList<>();
		action.add(actionBuilder.build());
		actionsBuilder.setAction(action);
		actionsCaseBuilder.setApplyActions(actionsBuilder.build());
		instructionBuilder.setInstruction(actionsCaseBuilder.build());
		List<Instruction> instructions = new ArrayList<>();
		instructions.add(instructionBuilder.build());
		instructionsBuilder.setInstruction(instructions);
		builder.setInstructions(instructionsBuilder.build());
		// 设置其他项
		builder.setPriority(50);
		builder.setHardTimeout(9999);
		builder.setIdleTimeout(9999);
		return builder.build();
	}
	private List<Node> getAllNodes(DataBroker dataBroker) {
		InstanceIdentifier.InstanceIdentifierBuilder<Nodes> noInstanceIdentifierBuilder = InstanceIdentifier.<Nodes>builder(Nodes.class);
		//InstanceIdentifier<Nodes> nodesIdentifier = InstanceIdentifier.builder(Nodes.class).build();
		Nodes nodes = null;
		try (ReadOnlyTransaction readOnlyTransaction = dataBroker.newReadOnlyTransaction()){
			Optional<Nodes> dataOptional = readOnlyTransaction.read(LogicalDatastoreType.OPERATIONAL, noInstanceIdentifierBuilder.build()).get();
			if (dataOptional.isPresent()) {
				nodes = dataOptional.get();
			}
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ExecutionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return nodes.getNode();
	}
}
