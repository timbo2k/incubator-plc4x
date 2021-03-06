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
package org.apache.plc4x.java.s7.messages.items;

import org.apache.plc4x.java.base.messages.items.DefaultBooleanFieldItem;
import org.apache.plc4x.java.s7.netty.model.types.TransportSize;

public class S7BooleanFieldItem extends DefaultBooleanFieldItem {

    private final TransportSize naturalDataType;

    public S7BooleanFieldItem(TransportSize naturalDataType, Boolean... values) {
        super(values);
        this.naturalDataType = naturalDataType;
   }

    @Override
    public Object getObject(int index) {
        switch (naturalDataType) {
            case BOOL:
                return getBoolean(index);
            case BYTE:
                return getBoolean(index);
            case WORD:
                return getBoolean(index);
            case DWORD:
                return getBoolean(index);
            case LWORD:
                return getBoolean(index);
            default:
                return null;
        }
    }

}

