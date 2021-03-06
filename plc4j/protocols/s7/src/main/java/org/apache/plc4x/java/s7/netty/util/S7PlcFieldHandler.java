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
package org.apache.plc4x.java.s7.netty.util;

import org.apache.plc4x.java.api.exceptions.PlcInvalidFieldException;
import org.apache.plc4x.java.api.exceptions.PlcRuntimeException;
import org.apache.plc4x.java.api.model.PlcField;
import org.apache.plc4x.java.base.connection.DefaultPlcFieldHandler;
import org.apache.plc4x.java.base.messages.items.DefaultLocalDateTimeFieldItem;
import org.apache.plc4x.java.base.messages.items.DefaultLongFieldItem;
import org.apache.plc4x.java.base.messages.items.FieldItem;
import org.apache.plc4x.java.s7.messages.items.*;
import org.apache.plc4x.java.s7.model.S7Field;
import org.apache.plc4x.java.s7.netty.model.types.TransportSize;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.BitSet;
import java.util.LinkedList;
import java.util.List;

public class S7PlcFieldHandler extends DefaultPlcFieldHandler {

    @Override
    public PlcField createField(String fieldQuery) throws PlcInvalidFieldException {
        if (S7Field.matches(fieldQuery)) {
            return S7Field.of(fieldQuery);
        }
        throw new PlcInvalidFieldException(fieldQuery);
    }

    @Override
    public FieldItem encodeBoolean(PlcField field, Object[] values) {
        S7Field s7Field = (S7Field) field;
        // All of these types are declared as Bit or Bit-String types.
        if ((s7Field.getDataType() == TransportSize.BOOL) || (s7Field.getDataType() == TransportSize.BYTE) ||
            (s7Field.getDataType() == TransportSize.WORD) || (s7Field.getDataType() == TransportSize.DWORD) ||
            (s7Field.getDataType() == TransportSize.LWORD)) {
            return internalEncodeBoolean(field, values);
        }
        throw new PlcRuntimeException("Invalid encoder for type " + s7Field.getDataType().name());
    }

    @Override
    public FieldItem encodeByte(PlcField field, Object[] values) {
        S7Field s7Field = (S7Field) field;
        if ((s7Field.getDataType() == TransportSize.BYTE) || (s7Field.getDataType() == TransportSize.SINT) ||
            (s7Field.getDataType() == TransportSize.USINT) || (s7Field.getDataType() == TransportSize.CHAR)) {
            return internalEncodeInteger(field, values);
        }
        throw new PlcRuntimeException("Invalid encoder for type " + s7Field.getDataType().name());
    }

    @Override
    public FieldItem encodeShort(PlcField field, Object[] values) {
        S7Field s7Field = (S7Field) field;
        if ((s7Field.getDataType() == TransportSize.WORD) || (s7Field.getDataType() == TransportSize.INT) ||
            (s7Field.getDataType() == TransportSize.UINT)) {
            return internalEncodeInteger(field, values);
        }
        throw new PlcRuntimeException("Invalid encoder for type " + s7Field.getDataType().name());
    }

    @Override
    public FieldItem encodeInteger(PlcField field, Object[] values) {
        S7Field s7Field = (S7Field) field;
        if ((s7Field.getDataType() == TransportSize.DWORD) || (s7Field.getDataType() == TransportSize.DINT) ||
            (s7Field.getDataType() == TransportSize.UDINT)) {
            return internalEncodeInteger(field, values);
        }
        throw new PlcRuntimeException("Invalid encoder for type " + s7Field.getDataType().name());
    }

    @Override
    public FieldItem encodeBigInteger(PlcField field, Object[] values) {
        S7Field s7Field = (S7Field) field;
        if ((s7Field.getDataType() == TransportSize.DWORD) || (s7Field.getDataType() == TransportSize.DINT) ||
            (s7Field.getDataType() == TransportSize.UDINT)) {
            return internalEncodeInteger(field, values);
        }
        throw new PlcRuntimeException("Invalid encoder for type " + s7Field.getDataType().name());
    }

    @Override
    public FieldItem encodeLong(PlcField field, Object[] values) {
        S7Field s7Field = (S7Field) field;
        if ((s7Field.getDataType() == TransportSize.LWORD) || (s7Field.getDataType() == TransportSize.LINT) ||
            (s7Field.getDataType() == TransportSize.ULINT)) {
            return internalEncodeInteger(field, values);
        }
        throw new PlcRuntimeException("Invalid encoder for type " + s7Field.getDataType().name());
    }

    @Override
    public FieldItem encodeFloat(PlcField field, Object[] values) {
        S7Field s7Field = (S7Field) field;
        if (s7Field.getDataType() == TransportSize.REAL) {
            return internalEncodeFloatingPoint(field, values);
        }
        throw new PlcRuntimeException("Invalid encoder for type " + s7Field.getDataType().name());
    }

    @Override
    public FieldItem encodeDouble(PlcField field, Object[] values) {
        S7Field s7Field = (S7Field) field;
        if (s7Field.getDataType() == TransportSize.LREAL) {
            return internalEncodeFloatingPoint(field, values);
        }
        throw new PlcRuntimeException("Invalid encoder for type " + s7Field.getDataType().name());
    }

    @Override
    public FieldItem encodeString(PlcField field, Object[] values) {
        S7Field s7Field = (S7Field) field;
        if ((s7Field.getDataType() == TransportSize.CHAR) || (s7Field.getDataType() == TransportSize.WCHAR) ||
            (s7Field.getDataType() == TransportSize.STRING) || (s7Field.getDataType() == TransportSize.WSTRING)) {
            return internalEncodeString(field, values);
        }
        throw new PlcRuntimeException("Invalid encoder for type " + s7Field.getDataType().name());
    }

    @Override
    public FieldItem encodeTime(PlcField field, Object[] values) {
        S7Field s7Field = (S7Field) field;
        if (s7Field.getDataType() == TransportSize.TIME) {
            return internalEncodeTemporal(field, values);
        }
        throw new PlcRuntimeException("Invalid encoder for type " + s7Field.getDataType().name());
    }

    @Override
    public FieldItem encodeDate(PlcField field, Object[] values) {
        S7Field s7Field = (S7Field) field;
        if (s7Field.getDataType() == TransportSize.DATE) {
            return internalEncodeTemporal(field, values);
        }
        throw new PlcRuntimeException("Invalid encoder for type " + s7Field.getDataType().name());
    }

    @Override
    public FieldItem encodeDateTime(PlcField field, Object[] values) {
        S7Field s7Field = (S7Field) field;
        if (s7Field.getDataType() == TransportSize.DATE_AND_TIME) {
            return internalEncodeTemporal(field, values);
        }
        throw new PlcRuntimeException("Invalid encoder for type " + s7Field.getDataType().name());
    }

    private FieldItem internalEncodeBoolean(PlcField field, Object[] values) {
        S7Field s7Field = (S7Field) field;
        switch (s7Field.getDataType()) {
            case BOOL:
            case BYTE:
            case WORD:
            case DWORD:
            case LWORD:
                break;
            default:
                throw new IllegalArgumentException(
                    "Cannot assign boolean values to " + s7Field.getDataType().name() + " fields.");
        }
        List<Boolean> booleanValues = new LinkedList<>();
        for (Object value : values) {
            if (value instanceof Boolean) {
                Boolean booleanValue = (Boolean) value;
                booleanValues.add(booleanValue);
            } else if (value instanceof Byte) {
                Byte byteValue = (Byte) value;
                BitSet bitSet = BitSet.valueOf(new byte[]{byteValue});
                for (int i = 0; i < 8; i++) {
                    booleanValues.add(bitSet.get(i));
                }
            } else if (value instanceof Short) {
                Short shortValue = (Short) value;
                BitSet bitSet = BitSet.valueOf(new long[]{shortValue});
                for (int i = 0; i < 16; i++) {
                    booleanValues.add(bitSet.get(i));
                }
            } else if (value instanceof Integer) {
                Integer integerValue = (Integer) value;
                BitSet bitSet = BitSet.valueOf(new long[]{integerValue});
                for (int i = 0; i < 32; i++) {
                    booleanValues.add(bitSet.get(i));
                }
            } else if (value instanceof Long) {
                long longValue = (Long) value;
                BitSet bitSet = BitSet.valueOf(new long[]{longValue});
                for (int i = 0; i < 64; i++) {
                    booleanValues.add(bitSet.get(i));
                }
            } else {
                throw new IllegalArgumentException(
                    "Value of type " + value.getClass().getName() +
                        " is not assignable to " + s7Field.getDataType().name() + " fields.");
            }
        }
        return new S7BooleanFieldItem(s7Field.getDataType(), booleanValues.toArray(new Boolean[0]));
    }

    private FieldItem internalEncodeInteger(PlcField field, Object[] values) {
        S7Field s7Field = (S7Field) field;
        BigInteger minValue;
        BigInteger maxValue;
        Class<? extends FieldItem> fieldType;
        switch (s7Field.getDataType()) {
            case BYTE:
                minValue = BigInteger.valueOf((long) Byte.MIN_VALUE);
                maxValue = BigInteger.valueOf((long) Byte.MAX_VALUE);
                fieldType = S7LongFieldItem.class;
                break;
            case WORD:
                minValue = BigInteger.valueOf((long) Short.MIN_VALUE);
                maxValue = BigInteger.valueOf((long) Short.MAX_VALUE);
                fieldType = S7LongFieldItem.class;
                break;
            case DWORD:
                minValue = BigInteger.valueOf((long) Integer.MIN_VALUE);
                maxValue = BigInteger.valueOf((long) Integer.MAX_VALUE);
                fieldType = S7LongFieldItem.class;
                break;
            case LWORD:
                minValue = BigInteger.valueOf(Long.MIN_VALUE);
                maxValue = BigInteger.valueOf(Long.MAX_VALUE);
                fieldType = S7LongFieldItem.class;
                break;
            case SINT:
                minValue = BigInteger.valueOf((long) Byte.MIN_VALUE);
                maxValue = BigInteger.valueOf((long) Byte.MAX_VALUE);
                fieldType = S7LongFieldItem.class;
                break;
            case USINT:
                minValue = BigInteger.valueOf((long) 0);
                maxValue = BigInteger.valueOf((long) Byte.MAX_VALUE * 2);
                fieldType = S7LongFieldItem.class;
                break;
            case INT:
                minValue = BigInteger.valueOf((long) Short.MIN_VALUE);
                maxValue = BigInteger.valueOf((long) Short.MAX_VALUE);
                fieldType = S7LongFieldItem.class;
                break;
            case UINT:
                minValue = BigInteger.valueOf((long) 0);
                maxValue = BigInteger.valueOf(((long) Short.MAX_VALUE) * 2);
                fieldType = S7LongFieldItem.class;
                break;
            case DINT:
                minValue = BigInteger.valueOf((long) Integer.MIN_VALUE);
                maxValue = BigInteger.valueOf((long) Integer.MAX_VALUE);
                fieldType = S7LongFieldItem.class;
                break;
            case UDINT:
                minValue = BigInteger.valueOf((long) 0);
                maxValue = BigInteger.valueOf(((long) Integer.MAX_VALUE) * 2);
                fieldType = S7LongFieldItem.class;
                break;
            case LINT:
                minValue = BigInteger.valueOf(Long.MIN_VALUE);
                maxValue = BigInteger.valueOf(Long.MAX_VALUE);
                fieldType = S7LongFieldItem.class;
                break;
            case ULINT:
                minValue = BigInteger.valueOf((long) 0);
                maxValue = BigInteger.valueOf(Long.MAX_VALUE).multiply(BigInteger.valueOf((long) 2));
                fieldType = S7BigIntegerFieldItem.class;
                break;
            default:
                throw new IllegalArgumentException(
                    "Cannot assign integer values to " + s7Field.getDataType().name() + " fields.");
        }
        if (fieldType == DefaultLongFieldItem.class) {
            Long[] longValues = new Long[values.length];
            for (int i = 0; i < values.length; i++) {
                if (!((values[i] instanceof Byte) || (values[i] instanceof Short) ||
                    (values[i] instanceof Integer) || (values[i] instanceof BigInteger) || (values[i] instanceof Long))) {
                    throw new IllegalArgumentException(
                        "Value of type " + values[i].getClass().getName() +
                            " is not assignable to " + s7Field.getDataType().name() + " fields.");
                }
                BigInteger value = BigInteger.valueOf(((Number) values[i]).longValue());
                if (minValue.compareTo(value) > 0) {
                    throw new IllegalArgumentException(
                        "Value of " + value.toString() + " exceeds allowed minimum for type "
                            + s7Field.getDataType().name() + " (min " + minValue.toString() + ")");
                }
                if (maxValue.compareTo(value) < 0) {
                    throw new IllegalArgumentException(
                        "Value of " + value.toString() + " exceeds allowed maximum for type "
                            + s7Field.getDataType().name() + " (max " + maxValue.toString() + ")");
                }
                longValues[i] = value.longValue();
            }
            return new S7LongFieldItem(s7Field.getDataType(), longValues);
        } else {
            BigInteger[] bigIntegerValues = new BigInteger[values.length];
            for (int i = 0; i < values.length; i++) {
                BigInteger value;
                if (values[i] instanceof BigInteger) {
                    value = (BigInteger) values[i];
                } else if (((values[i] instanceof Byte) || (values[i] instanceof Short) ||
                    (values[i] instanceof Integer) || (values[i] instanceof Long))) {
                    value = BigInteger.valueOf(((Number) values[i]).longValue());
                } else {
                    throw new IllegalArgumentException(
                        "Value of type " + values[i].getClass().getName() +
                            " is not assignable to " + s7Field.getDataType().name() + " fields.");
                }
                if (minValue.compareTo(value) > 0) {
                    throw new IllegalArgumentException(
                        "Value of " + value.toString() + " exceeds allowed minimum for type "
                            + s7Field.getDataType().name() + " (min " + minValue.toString() + ")");
                }
                if (maxValue.compareTo(value) < 0) {
                    throw new IllegalArgumentException(
                        "Value of " + value.toString() + " exceeds allowed maximum for type "
                            + s7Field.getDataType().name() + " (max " + maxValue.toString() + ")");
                }
                bigIntegerValues[i] = value;
            }
            return new S7BigIntegerFieldItem(s7Field.getDataType(), bigIntegerValues);
        }
    }

    private FieldItem internalEncodeFloatingPoint(PlcField field, Object[] values) {
        S7Field s7Field = (S7Field) field;
        Double minValue;
        Double maxValue;
        switch (s7Field.getDataType()) {
            case REAL:
                // Yes this is actually correct, if I set min to Float.MIN_VALUE (0.0 < Float.MIN_VALUE = true)
                minValue = (double) -Float.MAX_VALUE;
                maxValue = (double) Float.MAX_VALUE;
                break;
            case LREAL:
                // Yes this is actually correct, if I set min to Double.MIN_VALUE (0.0 < Double.MIN_VALUE = true)
                minValue = -Double.MAX_VALUE;
                maxValue = Double.MAX_VALUE;
                break;
            default:
                throw new IllegalArgumentException(
                    "Cannot assign floating point values to " + s7Field.getDataType().name() + " fields.");
        }
        Double[] floatingPointValues = new Double[values.length];
        for (int i = 0; i < values.length; i++) {
            if (values[i] instanceof Float) {
                floatingPointValues[i] = ((Float) values[i]).doubleValue();
            } else if (values[i] instanceof Double) {
                floatingPointValues[i] = (Double) values[i];
            } else {
                throw new IllegalArgumentException(
                    "Value of type " + values[i].getClass().getName() +
                        " is not assignable to " + s7Field.getDataType().name() + " fields.");
            }
            if (floatingPointValues[i] < minValue) {
                throw new IllegalArgumentException(
                    "Value of " + floatingPointValues[i] + " exceeds allowed minimum for type "
                        + s7Field.getDataType().name() + " (min " + minValue.toString() + ")");
            }
            if (floatingPointValues[i] > maxValue) {
                throw new IllegalArgumentException(
                    "Value of " + floatingPointValues[i] + " exceeds allowed maximum for type "
                        + s7Field.getDataType().name() + " (max " + maxValue.toString() + ")");
            }
        }
        return new S7FloatingPointFieldItem(s7Field.getDataType(), floatingPointValues);
    }

    private FieldItem internalEncodeString(PlcField field, Object[] values) {
        S7Field s7Field = (S7Field) field;
        int maxLength;
        boolean encoding16Bit;
        switch (s7Field.getDataType()) {
            case CHAR:
                maxLength = 1;
                encoding16Bit = false;
                break;
            case WCHAR:
                maxLength = 1;
                encoding16Bit = true;
                break;
            case STRING:
                maxLength = 254;
                encoding16Bit = false;
                break;
            case WSTRING:
                maxLength = 254;
                encoding16Bit = true;
                break;
            default:
                throw new IllegalArgumentException(
                    "Cannot assign string values to " + s7Field.getDataType().name() + " fields.");
        }
        List<String> stringValues = new LinkedList<>();
        for (Object value : values) {
            if (value instanceof String) {
                String stringValue = (String) value;
                if (stringValue.length() > maxLength) {
                    throw new IllegalArgumentException(
                        "String length " + stringValue.length() + " exceeds allowed maximum for type "
                            + s7Field.getDataType().name() + " (max " + maxLength + ")");
                }
                stringValues.add(stringValue);
            }
            // All other types just translate to max one String character.
            else if (value instanceof Byte) {
                Byte byteValue = (Byte) value;
                byte[] stringBytes = new byte[]{byteValue};
                if (encoding16Bit) {
                    stringValues.add(new String(stringBytes, Charset.forName("UTF-16")));
                } else {
                    stringValues.add(new String(stringBytes, Charset.forName("UTF-8")));
                }
            } else if (value instanceof Short) {
                Short shortValue = (Short) value;
                byte[] stringBytes = new byte[2];
                stringBytes[0] = (byte) (shortValue >> 8);
                stringBytes[1] = (byte) (shortValue & 0xFF);
                if (encoding16Bit) {
                    stringValues.add(new String(stringBytes, Charset.forName("UTF-16")));
                } else {
                    stringValues.add(new String(stringBytes, Charset.forName("UTF-8")));
                }
            } else if (value instanceof Integer) {
                Integer integerValue = (Integer) value;
                byte[] stringBytes = new byte[4];
                stringBytes[0] = (byte) ((integerValue >> 24) & 0xFF);
                stringBytes[1] = (byte) ((integerValue >> 16) & 0xFF);
                stringBytes[2] = (byte) ((integerValue >> 8) & 0xFF);
                stringBytes[3] = (byte) (integerValue & 0xFF);
                if (encoding16Bit) {
                    stringValues.add(new String(stringBytes, Charset.forName("UTF-16")));
                } else {
                    stringValues.add(new String(stringBytes, Charset.forName("UTF-8")));
                }
            } else if (value instanceof Long) {
                Long longValue = (Long) value;
                byte[] stringBytes = new byte[8];
                stringBytes[0] = (byte) ((longValue >> 56) & 0xFF);
                stringBytes[1] = (byte) ((longValue >> 48) & 0xFF);
                stringBytes[2] = (byte) ((longValue >> 40) & 0xFF);
                stringBytes[3] = (byte) ((longValue >> 32) & 0xFF);
                stringBytes[4] = (byte) ((longValue >> 24) & 0xFF);
                stringBytes[5] = (byte) ((longValue >> 16) & 0xFF);
                stringBytes[6] = (byte) ((longValue >> 8) & 0xFF);
                stringBytes[7] = (byte) (longValue & 0xFF);
                if (encoding16Bit) {
                    stringValues.add(new String(stringBytes, Charset.forName("UTF-16")));
                } else {
                    stringValues.add(new String(stringBytes, Charset.forName("UTF-8")));
                }
            } else {
                throw new IllegalArgumentException(
                    "Value of type " + value.getClass().getName() +
                        " is not assignable to " + s7Field.getDataType().name() + " fields.");
            }
        }
        return new S7StringFieldItem(s7Field.getDataType(), stringValues.toArray(new String[0]));
    }

    private FieldItem internalEncodeTemporal(PlcField field, Object[] values) {
        S7Field s7Field = (S7Field) field;
        switch (s7Field.getDataType()) {
            case TIME:
            case DATE:
            case DATE_AND_TIME:
                return new DefaultLocalDateTimeFieldItem();
            default:
                throw new IllegalArgumentException(
                    "Cannot assign temporal values to " + s7Field.getDataType().name() + " fields.");
        }
    }

}
