/*
 * Copyright © 2017 no and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

package org.opendaylight.defender.impl;

import java.util.Arrays;

public class PacketParsing {
        //Packet Parser for the Packet_In messages received at the Controller.   
	    /**
	     * 数组中目的MAC地址的起始位置
	     */
	    private static final int DST_MAC_START_POSITION = 0;

	    /**
	     * 数组中目的MAC地址的截止位置
	     */
	    private static final int DST_MAC_END_POSITION = 6;

	    /**
	     * start position of source MAC address in array
	     */
	    private static final int SRC_MAC_START_POSITION = 6;

	    /**
	     * end position of source MAC address in array
	     */
	    private static final int SRC_MAC_END_POSITION = 12;

	    /**
	     * start position of ethernet type in array
	     */
	    private static final int ETHER_TYPE_START_POSITION = 12;

	    /**
	     * end position of ethernet type in array
	     */
	    private static final int ETHER_TYPE_END_POSITION = 14;

	    /**
	     * start position of IP Protocol in array
	     */
	    private static final int IP_PROTOCOL_START_POSITION = 23;

	    /**
	     * end position of IP Protocol in array
	     */
	    private static final int IP_PROTOCOL_END_POSITION = 24;

	    /**
	     * start position of source IP address in array
	     */
	    private static final int SRC_IP_START_POSITION = 26;

	    /**
	     * end position of source IP address in array
	     */
	    private static final int SRC_IP_END_POSITION = 30;

	    /**
	     * start position of Destination IP address in array
	     */
	    private static final int DST_IP_START_POSITION = 30;

	    /**
	     * end position of Destination IP address in array
	     */
	    private static final int DST_IP_END_POSITION = 34;

	    /**
	     * start position of source TCP/UDP Port in array
	     */
	    private static final int SRC_PORT_START_POSITION = 34;

	    /**
	     * end position of source TCP/UDP Port  in array
	     */
	    private static final int SRC_PORT_END_POSITION = 36;

	    /**
	     * start position of Destination TCP/UDP Port  in array
	     */
	    private static final int DST_PORT_START_POSITION = 36;

	    /**
	     * end position of DestinationTCP/UDP Port in array
	     */
	    private static final int DST_PORT_END_POSITION = 38;
	    
	    private PacketParsing() {
	        //prohibit to instantiate this class
	    }
	    //先从payload字节数据中抽取出对应字节位置上的字段内容
	    /**
	     * @param payload
	     * @return destination MAC address
	     */
	    public static byte[] extractDstMac(final byte[] payload) {
	        return Arrays.copyOfRange(payload, DST_MAC_START_POSITION, DST_MAC_END_POSITION);
	    }

	    /**
	     * @param payload
	     * @return source MAC address
	     */
	    public static byte[] extractSrcMac(final byte[] payload) {
	        return Arrays.copyOfRange(payload, SRC_MAC_START_POSITION, SRC_MAC_END_POSITION);
	    }

	    /**
	     * @param payload
	     * @return Ether Type
	     */
	    public static byte[] extractEtherType(final byte[] payload) {
	        return Arrays.copyOfRange(payload, ETHER_TYPE_START_POSITION, ETHER_TYPE_END_POSITION);
	    }

	    /**
	     * @param payload
	     * @return IP Protocol
	     */
	    public static byte[] extractIPProtocol(final byte[] payload) {
	        return Arrays.copyOfRange(payload, IP_PROTOCOL_START_POSITION, IP_PROTOCOL_END_POSITION);
	    }

	    /**
	     * @param payload
	     * @return destination IP address
	     */
	    public static byte[] extractDstIP(final byte[] payload) {
	        return Arrays.copyOfRange(payload, DST_IP_START_POSITION, DST_IP_END_POSITION);
	    }

	    /**
	     * @param payload
	     * @return source IP address
	     */
	    public static byte[] extractSrcIP(final byte[] payload) {
	        return Arrays.copyOfRange(payload, SRC_IP_START_POSITION, SRC_IP_END_POSITION);
	    }

	    /**
	     * @param payload
	     * @return Source TCP Port
	     */
	    public static byte[] extractSrcPort(final byte[] payload) {
	        return Arrays.copyOfRange(payload, SRC_PORT_START_POSITION, SRC_PORT_END_POSITION);
	    }

	    /**
	     * @param payload
	     * @return Destination TCP Port
	     */
	    public static byte[] extractDstPort(final byte[] payload) {
	        return Arrays.copyOfRange(payload, DST_PORT_START_POSITION, DST_PORT_END_POSITION);
	    }
	    
     /**
     * @param rawMac
     * @return String Mac Address
     */
    public static String rawMacToString(byte[] rawMac) {
        if (rawMac != null && rawMac.length == 6) {
            //可以实现对string类型的多次修改
        	StringBuilder sb = new StringBuilder();
            for (byte octet : rawMac) {
               //octet也表示8bits，但是此处只为一个变量
               //%02X表示以16进制输出，2为指定输出的宽度，如果位数小于2,则左端补0.
                sb.append(String.format(":%02X", octet));
            }
            //返回一个新的string，包含此字符序列当前所包含的字符子序列
            return sb.substring(1);
        }
        return null;
    }
    /**
     * @param rawIPProto
     * @return String IPProtocol
     */

    public static String rawIPProtoToString(byte[] rawIPProto) {
        if (rawIPProto != null && rawIPProto.length == 1) {
        	StringBuilder sb = new StringBuilder();
            for (byte octet : rawIPProto) {
            	//协议用十进制数表示
                sb.append(String.format(".%d", octet));
            }
            return sb.substring(1);
        }
        return null;
    }
    /**
     * @param rawIP
     * @return String IPAddress
     */
    public static String rawIPToString(byte[] rawIP) {
        if (rawIP != null && rawIP.length == 4) {
            StringBuilder sb = new StringBuilder();
            for (byte octet : rawIP) {
            	//IP用十进制数表示
                sb.append(String.format(".%d", octet));
            }
            return sb.substring(1);
        }
        return null;
    }

    /**
     * @param rawPort
     * @return int TCPPort
     */

    public static int rawPortToInteger(byte[] rawPort) {
        int intOctet =0;
        int intOctetSum = 0;
        int iter = 1;
        if (rawPort != null && rawPort.length == 2) {
            for (byte octet : rawPort) {
            	//byte转化为int，需要与0xff
            	//涉及java二元运算中数据类型的自动提升，如果操作数中不存在double、float、long，则结果均为int
            	//即在与0xff运算的过程中，octet已经转化为int类型，所以要保证后8位仍为octet原本的数据
                intOctet = octet & 0xff;
                intOctetSum = (int) (intOctetSum + intOctet *  Math.pow(256,iter));
                iter--;
            }
            return intOctetSum;
        }
        return 0;
    }

    /**
     * @param rawEthType
     * @return String EthType
     */

    public static String rawEthTypeToString(byte[] rawEthType) {
        if (rawEthType != null && rawEthType.length == 2) {
            StringBuilder sb = new StringBuilder();
            for (byte octet: rawEthType) {
                sb.append(String.format(":%02X", octet));
            }
            return sb.substring(1);
        }
        return null;
    }
}
