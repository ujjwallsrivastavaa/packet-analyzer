package com.packetanalyzer;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

final class BlockingRules {
    private final Set<Long> blockedIps = ConcurrentHashMap.newKeySet();
    private final Set<AppType> blockedApps = ConcurrentHashMap.newKeySet();
    private final Set<String> blockedDomains = ConcurrentHashMap.newKeySet();

    void blockIp(String ip) {
        long value = BinaryUtil.parseIp(ip);
        blockedIps.add(value);
        System.out.println("[Rules] Blocked IP: " + ip);
    }

    void blockApp(String app) {
        AppType type = AppType.fromLabel(app);
        if (type == AppType.UNKNOWN) {
            System.err.println("[Rules] Unknown app: " + app);
            return;
        }

        blockedApps.add(type);
        System.out.println("[Rules] Blocked app: " + type.displayName());
    }

    void blockDomain(String domain) {
        blockedDomains.add(domain == null ? "" : domain);
        System.out.println("[Rules] Blocked domain: " + domain);
    }

    boolean isBlocked(long srcIp, AppType app, String sni) {
        if (blockedIps.contains(srcIp)) {
            return true;
        }
        if (blockedApps.contains(app)) {
            return true;
        }

        for (String domain : blockedDomains) {
            if (!domain.isEmpty() && sni != null && sni.contains(domain)) {
                return true;
            }
        }

        return false;
    }
}