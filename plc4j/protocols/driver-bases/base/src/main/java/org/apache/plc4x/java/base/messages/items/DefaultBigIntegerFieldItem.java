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
package org.apache.plc4x.java.base.messages.items;

import java.math.BigDecimal;
import java.math.BigInteger;

public class DefaultBigIntegerFieldItem extends FieldItem<BigInteger> {

    public DefaultBigIntegerFieldItem(BigInteger... values) {
        super(values);
    }

    @Override
    public Object getObject(int index) {
        return getLong(index);
    }

    @Override
    public boolean isValidBoolean(int index) {
        return (getValue(index) != null);
    }

    @Override
    public Boolean getBoolean(int index) {
        if (isValidBoolean(index)) {
            return getValue(index).compareTo(BigInteger.ZERO) == 0;
        }
        return null;
    }

    @Override
    public boolean isValidByte(int index) {
        BigInteger value = getValue(index);
        return (value != null) && (value.compareTo(BigInteger.valueOf(Byte.MAX_VALUE)) < 0) &&
            (value.compareTo(BigInteger.valueOf(Byte.MIN_VALUE)) > 0);
    }

    @Override
    public Byte getByte(int index) {
        if (isValidByte(index)) {
            return getValue(index).byteValue();
        }
        return null;
    }

    @Override
    public boolean isValidShort(int index) {
        BigInteger value = getValue(index);
        return (value != null) && (value.compareTo(BigInteger.valueOf(Short.MAX_VALUE)) < 0) &&
            (value.compareTo(BigInteger.valueOf(Short.MIN_VALUE)) > 0);
    }

    @Override
    public Short getShort(int index) {
        if (isValidShort(index)) {
            return getValue(index).shortValue();
        }
        return null;
    }

    @Override
    public boolean isValidInteger(int index) {
        BigInteger value = getValue(index);
        return (value != null) && (value.compareTo(BigInteger.valueOf(Integer.MAX_VALUE)) < 0) &&
            (value.compareTo(BigInteger.valueOf(Integer.MIN_VALUE)) > 0);
    }

    @Override
    public Integer getInteger(int index) {
        if (isValidInteger(index)) {
            BigInteger value = getValue(index);
            return value.intValue();
        }
        return null;
    }

    public boolean isValidBigInteger(int index) {
        BigInteger value = getValue(index);
        return value != null;
    }

    public BigInteger getBigInteger(int index) {
        if (isValidBigInteger(index)) {
            return getValue(index);
        }
        return null;
    }

    @Override
    public boolean isValidLong(int index) {
        BigInteger value = getValue(index);
        return (value != null) && (value.compareTo(BigInteger.valueOf(Long.MAX_VALUE)) < 0) &&
            (value.compareTo(BigInteger.valueOf(Long.MIN_VALUE)) > 0);
    }

    @Override
    public Long getLong(int index) {
        if (isValidLong(index)) {
            BigInteger value = getValue(index);
            return value.longValue();
        }
        return null;
    }

    @Override
    public boolean isValidFloat(int index) {
        BigInteger value = getValue(index);
        if (value == null) {
            return false;
        }
        BigDecimal decimalValue = new BigDecimal(value);
        return (decimalValue.compareTo(BigDecimal.valueOf(Float.MAX_VALUE)) < 0) &&
            (decimalValue.compareTo(BigDecimal.valueOf(Float.MIN_VALUE)) > 0);
    }

    @Override
    public Float getFloat(int index) {
        if (isValidFloat(index)) {
            return getValue(index).floatValue();
        }
        return null;
    }

    @Override
    public boolean isValidDouble(int index) {
        BigInteger value = getValue(index);
        if (value == null) {
            return false;
        }
        BigDecimal decimalValue = new BigDecimal(value);
        return (decimalValue.compareTo(BigDecimal.valueOf(Double.MAX_VALUE)) < 0) &&
            (decimalValue.compareTo(BigDecimal.valueOf(Double.MIN_VALUE)) > 0);
    }

    @Override
    public Double getDouble(int index) {
        if (isValidDouble(index)) {
            return getValue(index).doubleValue();
        }
        return null;
    }

    public boolean isValidBigDecimal(int index) {
        return getValue(index) != null;
    }

    public BigDecimal getBigDecimal(int index) {
        return new BigDecimal(getValue(index));
    }

}

