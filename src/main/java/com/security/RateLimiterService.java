package com.security;

import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

@Service
public class RateLimiterService {
    private final int maxRequests = 10;
    private final int timeWindow = 1000*60;
    private final Map<String, UserRequestInfo> requestMap = new HashMap<>();

    public boolean isAllowed(String clientIp){
        long currentTime = System.currentTimeMillis();

        UserRequestInfo userRequestInfo = requestMap.computeIfAbsent(clientIp, ip->new UserRequestInfo(currentTime));
        synchronized (userRequestInfo){
            if (currentTime - userRequestInfo.getTimestamp() >= timeWindow){
                userRequestInfo.setTimestamp(currentTime);
                userRequestInfo.setRequestCount(new AtomicInteger(1));
                return true;
            }else {
                if (userRequestInfo.getRequestCount().get() < maxRequests){
                    userRequestInfo.setRequestCount(new AtomicInteger(userRequestInfo.getRequestCount().get() + 1));
                    return true;
                }else {
                    return false;
                }
            }
        }

    }
}
