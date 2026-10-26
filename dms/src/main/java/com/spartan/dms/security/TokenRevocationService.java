package com.spartan.dms.security;

import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Per-token logout.
 *
 * Previously logout set User.tokensValidSince = now, which killed EVERY
 * token of that account. The admin account is used from more than one
 * browser/device, so one person pressing "Logout" (or a second tab) instantly
 * logged everyone else out with "Session expired". Now logout only revokes
 * the one token that was used to call /auth/logout; other sessions stay
 * signed in until their own 24h expiry.
 */
@Component
public class TokenRevocationService {

    // token -> expiry (epoch millis). Entries are dropped once the token
    // would have expired anyway, so the map never grows without bound.
    private final Map<String, Long> revoked = new ConcurrentHashMap<>();

    public void revoke(String token, long expiresAtMillis) {
        if (token == null || token.isBlank()) return;
        cleanup();
        revoked.put(token, expiresAtMillis);
    }

    public boolean isRevoked(String token) {
        if (token == null) return false;
        Long exp = revoked.get(token);
        if (exp == null) return false;
        if (exp < System.currentTimeMillis()) {
            revoked.remove(token);
            return false;
        }
        return true;
    }

    private void cleanup() {
        long now = System.currentTimeMillis();
        revoked.entrySet().removeIf(e -> e.getValue() < now);
    }
}
