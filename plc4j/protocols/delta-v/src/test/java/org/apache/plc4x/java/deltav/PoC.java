/*
 Licensed to the Apache Software Foundation (ASF) under one
 or more contributor license agreements.  See the NOTICE file
 distributed with this work for additional information
 regarding copyright ownership.  The ASF licenses this file
 to you under the Apache License, Version 2.0 (the
 "License"); you may not use this file except in compliance
 with the License.  You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing,
 software distributed under the License is distributed on an
 "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 KIND, either express or implied.  See the License for the
 specific language governing permissions and limitations
 under the License.
 */

package org.apache.plc4x.java.deltav;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import org.apache.commons.codec.binary.Hex;
import org.pcap4j.core.*;
import org.pcap4j.packet.UdpPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class PoC {

    private static final Logger valueLogger = LoggerFactory.getLogger(PoC.class);

    private static final int SNAPLEN = 65536;
    private static final int READ_TIMEOUT = 10;

    private PcapHandle receiveHandle;

    private PoC() throws Exception {
        PcapNetworkInterface nif = null;
        for (PcapNetworkInterface dev : Pcaps.findAllDevs()) {
            if("en7".equals(dev.getName())) {
                nif = dev;
                break;
            }
        }

        if(nif == null) {
            throw new RuntimeException("Couldn't find network device");
        }

        // Setup receiving of packets and redirecting them to the corresponding listeners.
        // Filter packets to contain only the ip protocol number of the current protocol.
        receiveHandle = nif.openLive(SNAPLEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);

        // Set the filter.
        String filterString = "udp port 18507";
        receiveHandle.setFilter(filterString, BpfProgram.BpfCompileMode.OPTIMIZE);

        Map<String, Object> values = new HashMap<>();

        byte[] timeBytes = ByteBuffer.allocate(8).putLong(System.currentTimeMillis()).array();
        System.out.println("Current Time: " + Hex.encodeHexString(timeBytes));

        PacketListener packetListener = packet -> {
            try {
                UdpPacket udpPacket = (UdpPacket) packet.getPayload().getPayload();
                ByteBuf buf = Unpooled.wrappedBuffer(udpPacket.getPayload().getRawData());
                short header = buf.readShort();
                if(header != (short) 0xFACE) {
                    return;
                }
                short packetLength = buf.readShort();
                short messageType = buf.readShort();
                short messageId = buf.readShort();
                short senderId = buf.readShort();
                buf.skipBytes(3); // Timestamp
                buf.skipBytes(3); // 0x800400 or 0x000400

                // Messages with payload 0 are usually responses.
                if(packetLength == 0) {
                    return;
                }

                // We're only interested in type 2 messages.
                if(messageType == 0x0002) {
                    short payloadType = buf.readShort();
                    switch(payloadType) {
                        case 0x1B01: {
                            // NOTE:
                            // - Seems to be sent as soon as the OS start up and a screen is opened.
                            // - Sent from the controller to the OS
                            // - The end seems to be a string followed by 0xFFFF
                            //
                            // Found packets:
                            // 1b 01 00 00 00 00 00 07 03 8a 01 c4 00 04 00 1e
                            // 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                            // 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                            // 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                            // 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                            // 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                            // 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                            // 00 00 00 00 00 00 00 00 04 cf 1a 0b 00 35 01 2c
                            // 00 00 03 e8 00 00 00 05 00 49 00 44 00 49 00 53
                            // 00 50 00 00 ff ff 01
                            //
                            // 1b 01 00 00 00 00 00 07 03 8c 01 c6 00 04 00 30
                            // 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                            // 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                            // 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                            // 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                            // 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                            // 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                            // 00 00 00 00 00 00 00 00 04 cf 1a 0b 00 35 01 2c
                            // 00 00 03 e8 00 01 00 0e 00 43 00 2f 00 53 00 57
                            // 00 5f 00 4d 00 41 00 58 00 5f 00 53 00 43 00 41
                            // 00 4c 00 45 00 00 ff ff 01
                        }
                        case 0x1B02: {
                            // NOTE:
                            // - Seems to be sent as soon as the OS start up and a screen is opened.
                            // - Sent from the OS to the controller
                            // - Seems to be a response from the OS to the controller to a previous 0x1B01 message
                            // - Size of the response seems to be in direct correlation with the size of the corresponding 0x1B01 message
                            //
                            // Found packets:
                            // 1b 02 00 00 00 00 00 07 03 8a 01 c4 00 04 00 00
                            // 00 06 00 01 00 00 00 00 00 00 00 00 00 00 00 00
                            // 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                            // 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                            // 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                            // 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                            // 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                            // 00 00 00 00 00 00 00 00 01 00 00 00 00 00 35 01
                            // 2c 04 cf 1a 0b 03 00 00 00 00 00 1f 01
                            //
                            // 1b 02 00 00 00 00 00 07 03 8c 01 c6 00 04 00 00
                            // 00 06 00 01 00 00 00 00 00 00 00 00 00 00 00 00
                            // 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                            // 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                            // 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                            // 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                            // 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                            // 00 00 00 00 00 00 00 00 01 00 00 00 00 00 35 01
                            // 2c 04 cf 1a 0b 02 00 01 24 00 0e 43 48 00 00 c2
                            // 20 00 00 03 e9 01 01 5e 8a
                        }
                        case 0x0201: {
                            // Found packets:
                            // 02 01 00 42 0a 08 00 65 01 5a 00 59 00 00 00 00
                            // 00 00 00 00
                            //
                            // 02 01 00 00 00 00 00 65 01 de 00 18 00 00 00 00
                            // 00 00 00 00
                            System.out.println("Got 0x" + Hex.encodeHexString(new byte[]{(byte)(payloadType >> 8), (byte)(payloadType & 0xFF)}) + " packet from " + senderId);
                            outputPacket(buf);
                            break;
                        }
                        case 0x0202: {
                            // Note:
                            // - Seems to occur during connection establishment phase.

                            // Found packets:
                            // 02 02 00 00 00 00 00 65 01 de 00 18 00 00 00 00
                            // 00 06 00 00 00 00 00 00
                            break;
                        }
                        case 0x0301: {
                            // Note:
                            // - The controllers seem to send these messages
                            // - It seems that there are two variants of these packets:
                            //   - Short ones containing almost no information
                            //   - Long ones containing a pattern 14 bytes each starting with 0x04 an an incrementing byte value
                            // - Short messages seem to start with a short numeric value followed by
                            //      0a 08 00 66 00 00 00 00 00 00 00 00 00 04 00 00 00 00 00 00
                            //   finished by an increasing one-byte value which is increased by 2 for every packet
                            //   - The incremented number seems to be increased by 3 whenever a overrun would occur.
                            //     This causes the counter to have just even numbers for one run and then switch to odd ones
                            //     after the next over-run and then back to even ones after the next.
                            // - Big messages seem to contain some pattern of 14 bytes
                            //   - Each pattern seems to have the following pattern:
                            //     04 {incremented byte} 17 {ib + 0x29} 00 {ib + 0x1D} 00 {ib + 0x3A} 00 00 03 e8 00 00
                            //
                            // Found packets:
                            // (small)
                            // 03 01 00 2e 0a 08 00 66 00 00 00 00 00 00 00 00
                            // 00 04 00 00 00 00 00 00 c5
                            //
                            // (big)
                            // 03 01 00 00 00 00 00 53 00 00 00 00 00 00 00 00
                            // 00 04 00 00 00 00 00 00 23 04 1f 17 48 00 3c 00
                            // 59 00 00 03 e8 00 00 04 20 17 49 00 3d 00 5a 00
                            // 00 03 e8 00 00 04 21 17 4a 00 3e 00 5b 00 00 03
                            // e8 00 00 04 25 17 4e 00 42 00 5f 00 00 03 e8 00
                            // 00 04 26 17 4f 00 43 00 60 00 00 03 e8 00 00 04
                            // 27 17 50 00 44 00 61 00 00 03 e8 00 00 04 28 17
                            // 51 00 45 00 62 00 00 03 e8 00 00 04 23 17 4c 00
                            // 40 00 5d 00 00 03 e8 00 00 04 24 17 4d 00 41 00
                            // 5e 00 00 03 e8 00 00 04 2a 17 53 00 47 00 64 00
                            // 00 03 e8 00 00 04 2e 17 57 00 4b 00 68 00 00 03
                            // e8 00 00 04 31 17 5a 00 4e 00 6b 00 00 03 e8 00
                            // 00 04 36 17 5f 00 53 00 70 00 00 03 e8 00 00 04
                            // 37 17 60 00 54 00 71 00 00 03 e8 00 00 04 32 17
                            // 5b 00 4f 00 6c 00 00 03 e8 00 00 00 00 00 00
                            System.out.println("Got 0x" + Hex.encodeHexString(new byte[]{(byte)(payloadType >> 8), (byte)(payloadType & 0xFF)}) + " packet from " + senderId);
                            outputPacket(buf);
                            break;
                        }
                        case 0x0304: {
                            // Note:
                            // - The Operator Systems seem to be sending these messages.
                            // Found packets:
                            //   03 04 00 00 00 00 00 6b 00 00 00 00 00 00 00 00
                            //   00 04 00 00 00 00 00 00 49 00 86 00 01 1a 02 00
                            //   00 20 03 00 04 00 0b b6 9c 00 6b 00 00 2a cb e2
                            //   e6 f8 e0 00 00 2a cb e2 e6 f8 d4 00 00 00 00 00
                            //
                            //   11 00 50 00 54 00 30 00 39 00 2d 00 30 00 31 00
                            //   2f 00 4d 00 41 00 49 00 4e 00 54 00 5f 00 41 00
                            //   4c 00 4d 00 00
                            //
                            //   47 00
                            //
                            //   18 00 23 00 44 00 23 00 31
                            //   00 2c 00 34 00 2c 00 30 00 30 00 30 00 30 00 30
                            //   00 30 00 30 00 31 00 2c 00 30 00 30 00 30 00 30
                            //   00 30 00 30 00 30 00 30 00 00
                            //
                            //   08 00 00 00 00 ff
                            //   ff 00 86 00 01 1a 02 00 00 20 03 00 01 00 0b b6
                            //   9c 00 6b 00 00 2a cb e3 21 90 b3 00 00 2a cb e2
                            //   e6 f8 d4 00 00 00 00 00 11 00 50 00 54 00 30 00
                            //   39 00 2d 00 30 00 31 00 2f 00 4d 00 41 00 49 00
                            //   4e 00 54 00 5f 00 41 00 4c 00 4d 00 00 47 00 18
                            //   00 23 00 44 00 23 00 30 00 2c 00 34 00 2c 00 30
                            //   00 30 00 30 00 30 00 30 00 30 00 30 00 31 00 2c
                            //   00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 30
                            //   00 00 08 00 00 00 00 ff ff 00 50 00 01 02 02 00
                            //   00 00 3f 00 36 00 18 b6 9c 00 6b 00 00 2a cb e2
                            //   e3 b6 a4 00 00 00 00 00 00 00 00 00 00 00 00 00
                            //   08 00 41 00 43 00 4e 00 20 00 43 00 4f 00 4d 00
                            //   4d 00 00 47 00 07 00 45 00 53 00 31 00 30 00 36
                            //   00 30 00 31 00 00 47 ff ff ff ff 00 88 00 01 1a
                            //   01 00 00 20 04 00 02 00 07 b6 9c 00 6b 00 00 2a
                            //   cb cf 72 da a9 00 00 2a cb ce 66 db 1c 00 00 00
                            //   00 00 12 00 50 00 54 00 30 00 39 00 2d 00 30 00
                            //   31 00 2f 00 41 00 44 00 56 00 49 00 53 00 45 00
                            //   5f 00 41 00 4c 00 4d 00 00 47 00 18 00 23 00 44
                            //   00 23 00 30 00 2c 00 32 00 2c 00 30 00 30 00 30
                            //   00 39 00 30 00 30 00 30 00 45 00 2c 00 30 00 30
                            //   00 30 00 30 00 30 00 31 00 30 00 31 00 00 08 00
                            //   00 00 00 ff ff 00 7c 00 01 00 01 26 00 00 2d 00
                            //   05 00 03 b6 9c 00 6b 00 00 2a cb ce 66 42 66 00
                            //   00 2a cb ce 66 42 66 00 00 00 00 00 24 00 3a 00
                            //   55 00 4e 00 49 00 54 00 5f 00 50 00 54 00 30 00
                            //   39 00 3a 00 50 00 54 00 30 00 39 00 41 00 4c 00
                            //   41 00 43 00 31 00 4d 00 43 00 54 00 33 00 30 00
                            //   2f 00 4d 00 41 00 58 00 5f 00 53 00 43 00 48 00
                            //   41 00 4c 00 54 00 00 08 c2 20 00 00 08 43 43 00
                            //   00 ff ff 00 7c 00 01 00 01 26 00 00 35 00 05 00
                            //   03 b6 9c 00 6b 00 00 2a cb ce 66 42 6b 00 00 2a
                            //   cb ce 66 42 6b 00 00 00 00 00 24 00 3a 00 55 00
                            //   4e 00 49 00 54 00 5f 00 50 00 54 00 30 00 39 00
                            //   3a 00 50 00 54 00 30 00 39 00 41 00 4c 00 41 00
                            //   43 00 31 00 4d 00 43 00 54 00 33 00 30 00 2f 00
                            //   4d 00 49 00 4e 00 5f 00 53 00 43 00 48 00 41 00
                            //   4c 00 54 00 00 08 c2 20 00 00 08 c2 18 00 00 ff
                            //   ff ff ff
//                            System.out.println("Got 0x" + Hex.encodeHexString(new byte[]{(byte)(payloadType >> 8), (byte)(payloadType & 0xFF)}) + " packet from " + senderId);
//                            outputPacket(buf);
                            break;
                        }
                        case 0x0401: {
                            // Note:
                            // - Seems to be sent by the controller every 10-15 seconds.
                            // Found packets:
                            // 04 01 00 2a 0a 08 00 64 02 26 01 38 00 00 00 00
                            // 00 19 00 00 00 05 00 24 00 00 00 00 00 00 00 fa
                            // ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
                            // ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff c0
                            // 01 2e
//                            System.out.println("Got 0x" + Hex.encodeHexString(new byte[]{(byte)(payloadType >> 8), (byte)(payloadType & 0xFF)}) + " packet from " + senderId);
                            //outputPacket(buf);
                            break;
                        }
                        case 0x0402: {
                            // Note:
                            // - Seems to be a response to a 0x0401 packet and it seems to replicate 5 bytes sent in the 0x0401
                            // Found packets:
                            // 04 02 00 00 00 00 00 64 02 7d 01 8f 00 00 00 00
                            // 00 00 00 00 00 00 00 00 00 06 00 00 00 00 00 00
//                            System.out.println("Got 0x" + Hex.encodeHexString(new byte[]{(byte)(payloadType >> 8), (byte)(payloadType & 0xFF)}) + " packet from " + senderId);
                            //outputPacket(buf);
                            break;
                        }
                        case 0x0403: {
                            System.out.println("----------------------------------------------------------------------------------------");
                            //                        System.out.println(Hex.encodeHexString(udpPacket.getPayload().getRawData()).replaceAll("(.{2})", "$1 ").replaceAll("(.{48})", "$1\n"));
                            //                        System.out.println("----------------------");
                            // Skip the rest of the header.
                            buf.skipBytes(39);
                            int endOfLastBlock = buf.readerIndex();
                            int lastBlockSize = 0;
                            short currentContext = 0;
                            for (byte code = buf.readByte(); buf.readableBytes() > 2; code = buf.readByte()) {
                                short blockId = buf.readShort();
                                byte type = buf.readByte();

                                // First check the code of the next block ...
                                switch (code) {
                                    case (byte) 0x01: {
                                        switch (type) {
                                            case (byte) 0x01: {
                                                // - It seems that the ids of a variable seem to occur multiple times
                                                // - Also does it seem that this type of block sets some sort of context for following blocks
                                                // - After setting up a machine with a new OS, the type of every of these is 0x00

                                                // Found blocks:
                                                // 01 00 23 01 1a 04 32 1c fd (size 7)
                                                currentContext = blockId;
                                                buf.skipBytes(5);
                                                outputDetectedBlock("-- Switch Context --", buf, endOfLastBlock);
                                                break;
                                            }
                                            case (byte) 0x00: {
                                                // Is seems this simply signals the end of a packet.
                                                currentContext = blockId;
                                                buf.skipBytes(5);
                                                outputDetectedBlock("-- Switch Context --", buf, endOfLastBlock);
                                                break;
                                            }
                                            default: {
                                                dumpAndExit(buf, endOfLastBlock, lastBlockSize, "Unexpected 0x01 type code: " + Hex.encodeHexString(new byte[]{type}));
                                            }
                                        }
                                        break;
                                    }
                                    case (byte) 0x02: {
                                        // Now inspect the block content ...
                                        switch (type) {
                                            case (byte) 0x01: {
                                                // Possibly boolean value?
                                                String id = "BOOL-" + currentContext + "-" + blockId;
                                                byte booleanByteValue = buf.readByte();
                                                outputDetectedBlock("BOOL value", buf, endOfLastBlock);
                                                boolean booleanValue = false;
                                                switch (booleanByteValue) {
                                                    case (byte) 0x00:
                                                        booleanValue = false;
                                                        break;
                                                    case (byte) 0x01:
                                                        booleanValue = true;
                                                        break;
                                                    default:
                                                        System.out.println("Unknown second byte for boolean value 0x" + Hex.encodeHexString(new byte[]{booleanByteValue}));
                                                }
                                                if (!values.containsKey(id)) {
                                                    valueLogger.info(String.format("Variable with id: %s set to: %b", id, booleanValue));
                                                    values.put(id, booleanValue);
                                                } else if (!values.get(id).equals(booleanValue)) {
                                                    boolean oldValue = (boolean) values.get(id);
                                                    valueLogger.info(String.format("Variable with id: %s changed from: %b to: %b", id, oldValue, booleanValue));
                                                    values.put(id, booleanValue);
                                                }
                                                break;
                                            }
                                            case (byte) 0x03: {
                                                buf.skipBytes(5);
                                                outputDetectedBlock("Unknown", buf, endOfLastBlock);
                                                break;
                                            }
                                            case (byte) 0x05: {
                                                // NOTE:
                                                // - Each packet seems to have one of these
                                                // - For each following packet the content is identical
                                                // Found Block:
                                                // 02 00 0c 05: 00 02 00 13 63 00 00 69 9c 1a
                                                // 02 00 0c 05: 00 01 00 47 00 64 04 2a 17 53
                                                buf.skipBytes(10);
                                                outputDetectedBlock("Unknown", buf, endOfLastBlock);
                                                break;
                                            }
                                            case (byte) 0x06: {
                                                // Possibly Parse 16 bit int?
                                                String id = "(U)INT-" + currentContext + "-" + blockId;
                                                short shortValue = buf.readShort();
                                                outputDetectedBlock("(U)INT value", buf, endOfLastBlock);
                                                break;
                                            }
                                            case (byte) 0x07: {
                                                // Possibly Parse 32 bit int?
                                                String id = "(U)DINT-" + currentContext + "-" + blockId;
                                                int intValue = buf.readInt();
                                                outputDetectedBlock("(U)DINT value", buf, endOfLastBlock);
                                                break;
                                            }
                                            case (byte) 0x08: {
                                                // Parse float
                                                String id = "REAL-" + currentContext + "-" + blockId;
                                                float floatValue = buf.readFloat();
                                                outputDetectedBlock("REAL value", buf, endOfLastBlock);
                                                floatValue = Math.round(floatValue * 100.0f) / 100.0f;
                                                if (!values.containsKey(id)) {
                                                    valueLogger.info(String.format("Variable with id: %s set to: %f", id, floatValue));
                                                    values.put(id, floatValue);
                                                } else if (!values.get(id).equals(floatValue)) {
                                                    float oldValue = (float) values.get(id);
                                                    valueLogger.info(String.format("Variable with id: %s changed from: %f to: %f", id, oldValue, floatValue));
                                                    values.put(id, floatValue);
                                                }
                                                break;
                                            }
                                            case (byte) 0x21: {
                                                // From having a look at the byte values these could be 32bit floating point values with some sort of parameters
                                                String id = "REAL(P)-" + currentContext + "-" + blockId;
                                                byte param = buf.readByte();
                                                decodeParam(param);
                                                float floatValue = buf.readFloat();
                                                outputDetectedBlock("REAL(P) value", buf, endOfLastBlock);
                                                floatValue = Math.round(floatValue * 100.0f) / 100.0f;
                                                if (!values.containsKey(id)) {
                                                    valueLogger.info(String.format("Variable with id: %s set to: %f with params %s", id, floatValue, Hex.encodeHexString(new byte[]{param})));
                                                    values.put(id, floatValue);
                                                } else if (!values.get(id).equals(floatValue)) {
                                                    float oldValue = (float) values.get(id);
                                                    valueLogger.info(String.format("Variable with id: %s changed from: %f to: %f with params %s", id, oldValue, floatValue, Hex.encodeHexString(new byte[]{param})));
                                                    values.put(id, floatValue);
                                                }
                                                break;
                                            }
                                            case (byte) 0x22: {
                                                // Parse boolean (From what I learnt, this could be a flagged boolean, where the first byte is some sort of param)
                                                String id = "BOOL(P)-" + currentContext + "-" + blockId;
                                                byte param = buf.readByte();
                                                decodeParam(param);
                                                byte booleanByteValue = buf.readByte();
                                                outputDetectedBlock("BOOL(P) value", buf, endOfLastBlock);
                                                boolean booleanValue = false;
                                                switch (booleanByteValue) {
                                                    case (byte) 0x00:
                                                        booleanValue = false;
                                                        break;
                                                    case (byte) 0x01:
                                                        booleanValue = true;
                                                        break;
                                                    default:
                                                        System.out.println("Unknown second byte for boolean value 0x" + Hex.encodeHexString(new byte[]{booleanByteValue}));
                                                }
                                                if (!values.containsKey(id)) {
                                                    valueLogger.info(String.format("Variable with id: %s set to: %b with params %s", id, booleanValue, Hex.encodeHexString(new byte[]{param})));
                                                    values.put(id, booleanValue);
                                                } else if (!values.get(id).equals(booleanValue)) {
                                                    boolean oldValue = (boolean) values.get(id);
                                                    valueLogger.info(String.format("Variable with id: %s changed from: %b to: %b with params %s", id, oldValue, booleanValue, Hex.encodeHexString(new byte[]{param})));
                                                    values.put(id, booleanValue);
                                                }
                                                break;
                                            }
                                            case (byte) 0x24: {
                                                // No idea what this type is.
                                                // NOTE:
                                                // - It seems that the last byte seems to mirror the id of the block (Maybe the field id is just one byte and not a short)
                                                // - It seems that these blocks are contained in every packet.
                                                byte[] tmp = new byte[13]; // Has to be 13 in case of 0x0201 but some times 12
                                                buf.readBytes(tmp);
                                                outputDetectedBlock("Unknown", buf, endOfLastBlock);
                                                break;
                                            }
                                            case (byte) 0x25: {
                                                buf.skipBytes(6);
                                                outputDetectedBlock("Unknown", buf, endOfLastBlock);
                                                break;
                                            }
                                            case (byte) 0x47: {
                                                // No idea what this type is.
                                                // NOTE:
                                                // - Seems to be sent as soon as a user confirms an alarm.
                                                // - Seems the length is variable
                                                // - Seems content is terminated by a "0x0000" value
                                                // - All content seems to be encoded as short values with the first byte set to "0x00".
                                                //
                                                // Found Blocks:
                                                // 00 4b 00 22 00 49 00 6e 00 69 00 74 00 69 00 61
                                                // 00 6c 00 69 00 73 00 69 00 65 00 72 00 75 00 6e
                                                // 00 67 00 20 00 2e 00 2e 00 2e 00 2e 00 2e 00 20
                                                // 00 62 00 69 00 74 00 74 00 65 00 20 00 77 00 61
                                                // 00 72 00 74 00 65 00 6e 00 00 02 00 67 47 00 1d
                                                // 00 0b 00 57 00 41 00 52 00 54 00 45 00 4e 00 20
                                                // 00 2e 00 2e 00 2e 00 20 00 00
                                                short val = buf.readShort();
                                                while (val != 0x0000) {
                                                    val = buf.readShort();
                                                }
                                                outputDetectedBlock("Unknown", buf, endOfLastBlock);
                                                break;
                                            }
                                            case (byte) 0x48: {
                                                // No idea what this type is.
                                                // NOTE:
                                                // - Seems to be sent as soon as an alarm is fired, changed or removed from the controller.
                                                // - There seem to be only two types of values: 0x8000 and 0x8001
                                                byte[] tmp = new byte[2];
                                                buf.readBytes(tmp);
                                                outputDetectedBlock("Unknown", buf, endOfLastBlock);
                                                break;
                                            }
                                            case (byte) 0x49: {
                                                // - Judging from the 0x80 first byte I would assume this is again one of these parametrized values
                                                // - Would suggest this is a 32 bit integer value.
                                                // Found blocks:
                                                // 80 00 00 06 0d
                                                String id = "(U)DINT(P)-" + currentContext + "-" + blockId;
                                                byte param = buf.readByte();
                                                decodeParam(param);
                                                int intValue = buf.readInt();
                                                if (!values.containsKey(id)) {
                                                    valueLogger.info(String.format("Variable with id: %s set to: %d with params %s", id, intValue, Hex.encodeHexString(new byte[]{param})));
                                                    values.put(id, intValue);
                                                } else if (!values.get(id).equals(intValue)) {
                                                    int oldValue = (int) values.get(id);
                                                    valueLogger.info(String.format("Variable with id: %s changed from: %d to: %d with params %s", id, oldValue, intValue, Hex.encodeHexString(new byte[]{param})));
                                                    values.put(id, intValue);
                                                }
                                                outputDetectedBlock("(U)DINT(P) value", buf, endOfLastBlock);
                                                break;
                                            }
                                            case (byte) 0x5B: {
                                                // No idea what this type is.
                                                buf.readShort();
                                                outputDetectedBlock("Unknown", buf, endOfLastBlock);
                                            }
                                            case (byte) 0x63: {
                                                // No idea what this type is.
                                                // NOTE:
                                                // - It seems that this block is contained in every packet exactly once
                                                // Found blocks:
                                                // 02 00 06 63: 64 00 19 b9 88
                                                byte[] tmp = new byte[5];
                                                buf.readBytes(tmp);
                                                //                                            System.out.println(String.format("Got 0x63 type for id %s with content: %s", blockId, Hex.encodeHexString(tmp)));
                                                outputDetectedBlock("Unknown", buf, endOfLastBlock);
                                                break;
                                            }
                                            case (byte) 0x75: {
                                                // No idea what this type is.
                                                // NOTE:
                                                // - Exactly 3 blocks of this type with extremely similar content is being sent every 60 seconds for the ids: 17, 16 and 34
                                                //                            001600280d0100000000280015f360000000000100
                                                //                            001600280d0100000000280015f360000000000100
                                                int size = "001600280d0100000000280015f360000000000100".length() / 2; //21
                                                byte[] tmp = new byte[size];
                                                buf.readBytes(tmp);
                                                //                                            System.out.println(String.format("Got 0x75 type for id %s with content: %s", blockId, Hex.encodeHexString(tmp)));
                                                outputDetectedBlock("Unknown", buf, endOfLastBlock);
                                                break;
                                            }
                                            case (byte) 0x76: {
                                                // No idea what this type is.
                                                // These strange blocks containing a repeating pattern of 0x00 and 0xFF
                                                // NOTE:
                                                // - These blocks seem to be transferred whenever a boolean value is changed.
                                                // - There seem to be two variants:
                                                //   - Variant 1 (shorter) is transferred as soon as a boolean value is set
                                                //   - Variant 2 (longer) is transferred as soon as a boolean values is unset
                                                // - Variant always looks the same no matter what combination of boolean values is set
                                                // - The blocks always refer to ids 0, 1 and 2
                                                // - The additional part of Variant 2 always starts with:
                                                //   "000700420049004e005f0041004c004d000000180018000300002ae7"
                                                //   The last 4 bytes (maybe more) seem to be an always increasing value
                                                //   (Maybe some sort of timestamp)
                                                short length = (short) (buf.readShort() - 3);
                                                byte[] tmp = new byte[length];
                                                buf.readBytes(tmp);
                                                String hexBlock = Hex.encodeHexString(tmp).replaceAll("(.{32})", "$1\n");
                                                //                                            System.out.println(String.format("Got 0x76 type for id %s with content: \n%s", blockId, hexBlock));
                                                outputDetectedBlock("Unknown", buf, endOfLastBlock);
                                                break;
                                            }
                                            case (byte) 0xF6: {
                                                // Only seen in 0x0102 blocks
                                                buf.skipBytes(4);
                                                outputDetectedBlock("Unknown", buf, endOfLastBlock);
                                                break;
                                            }
                                            default: {
                                                dumpAndExit(buf, endOfLastBlock, lastBlockSize, "Unexpected 0x02 type code: " + Hex.encodeHexString(new byte[]{type}));
                                                /*if(code == (byte) 0x01) {
                                                    buf.skipBytes(4);
                                                } else {
                                                    dumpAndExit(buf, endOfLastBlock, lastBlockSize, "Unknown variable type 0x" + Hex.encodeHexString(new byte[]{type}));
                                                }
                                                outputDetectedBlock("Unknown", buf, endOfLastBlock);*/
                                            }

                                        }
                                        break;
                                    }
                                    case (byte) 0x03: {
                                        // TODO: Check if these other types still exist ..
                                        // Found blocks:
                                        // 03 00 23 00 00 00 4a             (size 6)
                                        // 03 01 00 27 01 1e 04 36 1d       (size 8)
                                        // 03 01 00 24 01 1b 04 33 1c fe    (size 9)
                                        switch (type) {
                                            case (byte) 0x00: {
                                                buf.skipBytes(3);
                                                break;
                                            }
                                            default: {
                                                dumpAndExit(buf, endOfLastBlock, lastBlockSize, "Unexpected 0x03 type code: " + Hex.encodeHexString(new byte[]{type}));
                                            }
                                        }
                                        break;
                                    }
                                    default: {
                                        dumpAndExit(buf, endOfLastBlock, lastBlockSize, "Unexpected code: " + Hex.encodeHexString(new byte[]{code}));
                                    }
                                }
                                lastBlockSize = buf.readerIndex() - endOfLastBlock;
                                endOfLastBlock = buf.readerIndex();
                            }
                            break;
                        }
                        case 0x0404: {
                            // Note:
                            // - Seems to be used during connection.
                            // Found Packets:
                            // 04 04 00 00 00 00 01 23 00 00 00 00 00 00 00 00
                            // 00 0a 00 00 00 00 00 00 00 00 00 00 00 07 00 45
                            // 00 53 00 31 00 30 00 36 00 30 00 31 00 00 ee a1
                            // ES10601 (The end seems to be a two byte per char encoded string with an ending 0x0000 value
                            // as well as a length information before the text (7 = number of chars in the string)
                        }
                        case 0x0501: {
                            // Seems to contain version information of the Operator System.
                            break;
                        }
                        case 0x0502: {
                            // Seems to contain version information of the Controller.
                            break;
                        }
                        case 0x0506: {
                            System.out.println("Got 0x" + Hex.encodeHexString(new byte[]{(byte)(payloadType >> 8), (byte)(payloadType & 0xFF)}) + " packet");
//                            outputPacket(buf);
                            break;
                        }
                        default: {
                            System.out.println("Got 0x" + Hex.encodeHexString(new byte[]{(byte)(payloadType >> 8), (byte)(payloadType & 0xFF)}) + " packet");
                            outputPacket(buf);
                        }
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        };

        ExecutorService pool = Executors.newScheduledThreadPool(2);
        pool.execute(() -> {
            try {
                receiveHandle.loop(-1, packetListener);
            } catch (PcapNativeException | InterruptedException | NotOpenException e) {
                e.printStackTrace();
            }
        });
    }

    protected void outputDetectedBlock(String name, ByteBuf byteBuf, int endOfLastBlock) {
        int blockSize = byteBuf.readerIndex() - endOfLastBlock;
        byte[] blockContent = new byte[blockSize];
        byteBuf.getBytes(endOfLastBlock, blockContent);
        String content = "   " + Hex.encodeHexString(blockContent).replaceAll("(.{2})", "$1 ");
//        System.out.println(String.format("Block: %20s %s", name, content));
    }

    protected void outputPacket(ByteBuf byteBuf) {
        String packetAsHexString = Hex.encodeHexString(byteBuf.array()).replaceAll("(.{2})", "$1 ").replaceAll("(.{48})", "$1\n");
        System.out.println(packetAsHexString);
    }

    protected void dumpAndExit(ByteBuf byteBuf, int endOfLastBlock, int lastBlockSize, String message) {
        int errorPos = byteBuf.readerIndex();
        int lastBlockStart = errorPos - endOfLastBlock;
        byteBuf.resetReaderIndex();
        System.out.println("-------------------- ERROR --------------------");
        String packetAsHexString = Hex.encodeHexString(byteBuf.array()).replaceAll("(.{2})", "$1 ").replaceAll("(.{48})", "$1\n");
        StringTokenizer stringTokenizer = new StringTokenizer(packetAsHexString, "\n");
        while (stringTokenizer.hasMoreElements()) {
            String line = stringTokenizer.nextToken();
            System.out.println(line);
            if((errorPos < 16) && (errorPos >= 0)) {
                StringBuffer sb = new StringBuffer();
                for(int i = 0; i < errorPos - 1; i++) {
                    sb.append("---");
                }
                sb.append("^");
                System.out.println(sb);
                System.out.println("Last block started: " + lastBlockStart + " bytes before error and had a size of: " + lastBlockSize);
                System.out.println(message);
                System.out.println("\n");
            }
            errorPos -= 16;
        }
        throw new RuntimeException("Error");
    }

    // These seem to be the values decoded for parametrized values ...
    private void decodeParam(byte param) {
        switch (param) {
            case (byte) 0x00: // 00000000
            case (byte) 0x88: // 10001000
            case (byte) 0x84: // 10000100
            case (byte) 0xC3: // 11000011
            case (byte) 0x0C: // 00001100
            case (byte) 0x80: // 10000000
            case (byte) 0xC0: // 11000000
                break;
            default:
                throw new RuntimeException("Unexpected param value " + param);
        }

    }

    public static void main(String[] args) throws Exception {
        new PoC();
    }

}
