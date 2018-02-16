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
package org.apache.plc4x.java.ads.api.commands.types;

import io.netty.buffer.ByteBuf;
import org.apache.plc4x.java.ads.api.util.ByteValue;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Date;

public class TimeStamp extends ByteValue {

    /**
     * @see <a href="https://github.com/java-native-access/jna/blob/master/contrib/platform/src/com/sun/jna/platform/win32/WinBase.java">java-native-access WinBase</a>
     */
    public final static BigInteger EPOCH_DIFF_IN_MILLIS = BigInteger.valueOf((369L * 365L + 89L) * 86400L * 1000L);

    public static final int NUM_BYTES = 8;

    protected final BigInteger bigIntegerValue;

    protected TimeStamp(byte... values) {
        super(values);
        assertLength(NUM_BYTES);
        bigIntegerValue = new BigInteger(new byte[]{
            // LE
            values[7],
            values[6],
            values[5],
            values[4],

            values[3],
            values[2],
            values[1],
            values[0],
        });
    }

    protected TimeStamp(BigInteger value) {
        super(ofBigInteger(value));
        assertLength(NUM_BYTES);
        bigIntegerValue = value;
    }

    protected static byte[] ofBigInteger(BigInteger value) {
        byte[] valueBytes = value.toByteArray();
        int length = valueBytes.length;
        return ByteBuffer.allocate(NUM_BYTES)
            // LE
            .put(length > 0 ? valueBytes[0] : 0)
            .put(length > 1 ? valueBytes[1] : 0)
            .put(length > 2 ? valueBytes[2] : 0)
            .put(length > 3 ? valueBytes[3] : 0)

            .put(length > 4 ? valueBytes[4] : 0)
            .put(length > 5 ? valueBytes[5] : 0)
            .put(length > 6 ? valueBytes[6] : 0)
            .put(length > 7 ? valueBytes[7] : 0)
            .array();
    }

    public static TimeStamp of(BigInteger value) {
        return new TimeStamp(javaToWinTime(value));
    }

    public static TimeStamp ofWinTime(BigInteger value) {
        return new TimeStamp(value);
    }

    public static TimeStamp of(long value) {
        return of(BigInteger.valueOf(value));
    }

    public static TimeStamp ofWinTime(long value) {
        return of(javaToWinTime(BigInteger.valueOf(value)));
    }

    public static TimeStamp of(byte... values) {
        return new TimeStamp(values);
    }

    public static TimeStamp of(Date timestamp) {
        BigInteger winStamp = javaToWinTime(BigInteger.valueOf(timestamp.getTime()));
        return new TimeStamp(winStamp);
    }

    public static TimeStamp of(ByteBuf byteBuf) {
        byte[] values = new byte[NUM_BYTES];
        byteBuf.readBytes(values);
        return of(values);
    }

    public BigInteger getBigIntegerValue() {
        return bigIntegerValue;
    }

    public Date getAsDate() {
        return new Date(winTimeToJava(bigIntegerValue).longValue());
    }

    public static BigInteger javaToWinTime(BigInteger timeMillisSince19700101) {
        BigInteger timeMillisSince16010101 = EPOCH_DIFF_IN_MILLIS.add(timeMillisSince19700101);
        return timeMillisSince16010101.multiply(BigInteger.valueOf(10_000));
    }

    public static BigInteger winTimeToJava(BigInteger winTime) {
        BigInteger timeMillisSince16010101 = winTime.divide(BigInteger.valueOf(10_000));
        return timeMillisSince16010101.subtract(EPOCH_DIFF_IN_MILLIS);
    }

    @Override
    public String toString() {
        return "TimeStamp{winTime=" + getBigIntegerValue() + "/date=" + getAsDate() + "} " + super.toString();
    }
}