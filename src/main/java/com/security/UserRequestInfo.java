package com.security;

import jdk.jfr.Name;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.concurrent.atomic.AtomicInteger;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserRequestInfo {
    private long timestamp;
    private AtomicInteger requestCount;

    UserRequestInfo(long timestamp) {
        this.timestamp = timestamp;
        this.requestCount = new AtomicInteger(1);
    }

}
