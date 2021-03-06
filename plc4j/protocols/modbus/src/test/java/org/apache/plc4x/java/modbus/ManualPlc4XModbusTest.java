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
package org.apache.plc4x.java.modbus;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.plc4x.java.PlcDriverManager;
import org.apache.plc4x.java.api.connection.PlcConnection;
import org.apache.plc4x.java.api.connection.PlcReader;
import org.apache.plc4x.java.api.connection.PlcWriter;
import org.apache.plc4x.java.api.messages.PlcReadResponse;
import org.apache.plc4x.java.api.messages.PlcWriteResponse;
import org.apache.plc4x.java.base.util.HexUtil;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Collection;
import java.util.stream.IntStream;

public class ManualPlc4XModbusTest {

    public static void main(String... args) {
        String connectionUrl;
        if (args.length > 0 && "serial".equalsIgnoreCase(args[0])) {
            System.out.println("Using serial");
            connectionUrl = "modbus:serial:///dev/ttys003";
        } else {
            System.out.println("Using tcp");
            connectionUrl = "modbus:tcp://localhost:5440";
        }
        try (PlcConnection plcConnection = new PlcDriverManager().getConnection(connectionUrl)) {
            System.out.println("PlcConnection " + plcConnection);

            {
                PlcReader reader = plcConnection.getReader().orElseThrow(() -> new RuntimeException("No Reader found"));

                PlcReadResponse<?> readResponse = reader.read(builder -> builder.addItem("randomRegister", "register:7[3]")).get();
                System.out.println("Response " + readResponse);
                readResponse.getAllByteArrays("randomRegister").stream()
                    .map(HexUtil::toHex)
                    .map(hex -> "Register Value: " + hex)
                    .forEach(System.out::println);
            }

            {
                // Read an int from 2 registers
                PlcReader reader = plcConnection.getReader().orElseThrow(() -> new RuntimeException("No Reader found"));

                // Just dump the actual values
                PlcReadResponse<?> readResponse = reader.read(builder -> builder.addItem("randomRegister", "register:3[2]")).get();
                System.out.println("Response " + readResponse);
                Collection<Byte[]> randomRegisters = readResponse.getAllByteArrays("randomRegister");
                randomRegisters.stream()
                    .map(HexUtil::toHex)
                    .map(hex -> "Register Value: " + hex)
                    .forEach(System.out::println);

                // Read an actual int
                Byte[] registerBytes = randomRegisters.stream()
                    .flatMap(Arrays::stream)
                    .toArray(Byte[]::new);
                int readInt = ByteBuffer.wrap(ArrayUtils.toPrimitive(registerBytes))
                    .order(ByteOrder.BIG_ENDIAN)
                    .getInt();
                System.out.println("Read int " + readInt + " from register");
            }

            {
                // Read an int from 2 registers and multiple requests
                PlcReader reader = plcConnection.getReader().orElseThrow(() -> new RuntimeException("No Reader found"));

                // Just dump the actual values
                PlcReadResponse<?> readResponse = reader.read(builder -> builder
                    .addItem("randomRegister1", "register:1[2]")
                    .addItem("randomRegister2", "register:10[3]")
                    .addItem("randomRegister3", "register:20[4]")
                    .addItem("randomRegister4", "register:30[5]")
                    .addItem("randomRegister5", "register:40[6]")
                ).get();
                System.out.println("Response " + readResponse);
                IntStream.range(1, 6).forEach(i -> {
                    Collection<Byte[]> randomRegisters = readResponse.getAllByteArrays("randomRegister" + i);
                    randomRegisters.stream()
                        .map(HexUtil::toHex)
                        .map(hex -> "Register " + i + " Value: " + hex)
                        .forEach(System.out::println);

                    // Read an actual int
                    Byte[] registerBytes = randomRegisters.stream()
                        .flatMap(Arrays::stream)
                        .toArray(Byte[]::new);
                    int readInt = ByteBuffer.wrap(ArrayUtils.toPrimitive(registerBytes))
                        .order(ByteOrder.BIG_ENDIAN)
                        .getInt();
                    System.out.println("Read int " + i + " " + readInt + " from register");
                });
            }

            {
                PlcReader reader = plcConnection.getReader().orElseThrow(() -> new RuntimeException("No Reader found"));

                PlcReadResponse<?> readResponse = reader.read(builder -> builder.addItem("randomCoil", "coil:1[9]")).get();
                System.out.println("Response " + readResponse);
                readResponse.getAllBooleans("randomCoil").stream()
                    .map(hex -> "Coil Value: " + hex)
                    .forEach(System.out::println);
            }

            {
                PlcWriter writer = plcConnection.getWriter().orElseThrow(() -> new RuntimeException("No Writer found"));

                PlcWriteResponse<?> writeResponse = writer.write(builder -> builder.addItem("randomCoilField", "coil:1", true)).get();
                System.out.println("Response " + writeResponse);
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
        System.exit(0);
    }
}
