package com.spartan.dms.security;

import com.spartan.dms.entity.User;
import com.spartan.dms.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.Optional;

/*
 * Staff portal (stafflogin site) -> DMS link.
 *
 * Portal server headers anuppum:
 *   X-Portal-Key   : PORTAL_INTEGRATION_KEY env value (rendu server-layum orey key)
 *   X-Portal-Phone : DP oda mobile number
 * Key sariya irundhaa, andha phone number oda DISTRIBUTOR login aagi irukra maadhiri
 * request ulla pogum. Appo DMS la irukra pazhaya rules ellaam (DP thanoda data
 * mattum paakalaam, stock check, ledger) apdiye work aagum.
 *
 * PORTAL_INTEGRATION_KEY empty-aa irundhaa indha filter edhuvum pannaadhu (OFF).
 * Indha class @Component illa — SecurityConfig la mattum add aagum, so
 * Spring Security chain-la orey thadava dhaan odum.
 */
@Slf4j
public class PortalIntegrationFilter extends OncePerRequestFilter {

    public static final String KEY_HEADER = "X-Portal-Key";
    public static final String PHONE_HEADER = "X-Portal-Phone";

    // Portal vazhiya DP use panra API mattum. Admin endpoints ithula illa.
    private static final List<String> ALLOWED = List.of(
            "/api/v1/integration/portal/",
            "/api/v1/warehouse/me",
            "/api/v1/product-requests",
            "/api/v1/products",
            "/api/v1/shops",
            "/api/v1/invoices",
            "/api/v1/sales-returns",
            "/api/v1/purchase-returns",
            "/api/v1/payments",
            "/api/v1/payment-proofs",
            "/api/v1/product-ledger",
            "/api/v1/stock-transfers"
    );

    private final String key;
    private final UserRepository userRepository;
    private final CustomUserDetailsService userDetailsService;

    public PortalIntegrationFilter(String key, UserRepository userRepository,
                                   CustomUserDetailsService userDetailsService) {
        this.key = key == null ? "" : key.trim();
        this.userRepository = userRepository;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {

        String sent = req.getHeader(KEY_HEADER);
        if (key.length() < 16 || sent == null || sent.isBlank()) {
            chain.doFilter(req, res);          // link OFF, or normal DMS user
            return;
        }
        if (!MessageDigest.isEqual(key.getBytes(StandardCharsets.UTF_8), sent.trim().getBytes(StandardCharsets.UTF_8))) {
            log.warn("Portal link: wrong key from {}", req.getRemoteAddr());
            deny(res, 401, "Portal link key is wrong.");
            return;
        }
        String path = req.getRequestURI();
        if (ALLOWED.stream().noneMatch(path::startsWith)) {
            deny(res, 403, "This DMS page is not open for the staff portal.");
            return;
        }

        Optional<User> user;
        try {
            user = findDistributor(req.getHeader(PHONE_HEADER));
        } catch (RuntimeException e) {
            log.warn("Portal link: DP lookup failed: {}", e.toString());
            deny(res, 500, "DMS could not check this Distributor right now.");
            return;
        }
        if (user.isEmpty()) {
            deny(res, 404, "No active DMS Distributor login with this mobile number. Ask Admin to check the DP mobile number in DMS.");
            return;
        }

        UserDetails ud = userDetailsService.loadUserByUsername(user.get().getUsername());
        if (!ud.isEnabled()) {
            deny(res, 403, "This Distributor is deactivated in DMS.");
            return;
        }
        UsernamePasswordAuthenticationToken auth =
                new UsernamePasswordAuthenticationToken(ud, null, ud.getAuthorities());
        SecurityContext ctx = SecurityContextHolder.createEmptyContext();
        ctx.setAuthentication(auth);
        SecurityContextHolder.setContext(ctx);
        try {
            chain.doFilter(req, res);
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    /** Phone number "+91 98765 43210", "098765...", "9876543210" — ellaame match aagum. */
    private Optional<User> findDistributor(String phone) {
        if (phone == null) return Optional.empty();
        String d = phone.replaceAll("\\D", "");
        if (d.length() > 10) d = d.substring(d.length() - 10);
        if (d.length() != 10) return Optional.empty();
        for (String v : List.of(d, "+91" + d, "91" + d, "0" + d, "+91 " + d)) {
            // findByMobileNumber leaves User.role LAZY (no session here) — reload by
            // username, which JOIN FETCHes the role, before reading role_name.
            Optional<User> u = userRepository.findByMobileNumber(v)
                    .flatMap(x -> userRepository.findByUsername(x.getUsername()))
                    .filter(x -> x.getRole() != null && SecurityUtils.ROLE_DISTRIBUTOR.equalsIgnoreCase(x.getRole().getRoleName()))
                    .filter(x -> x.getDistributor() != null)
                    .filter(x -> Boolean.TRUE.equals(x.getActive()))
                    .filter(x -> x.getApprovalStatus() == null
                            || x.getApprovalStatus() == com.spartan.dms.enums.ApprovalStatus.APPROVED);
            if (u.isPresent()) return u;
        }
        return Optional.empty();
    }

    private static void deny(HttpServletResponse res, int status, String msg) throws IOException {
        res.setStatus(status);
        res.setContentType("application/json;charset=UTF-8");
        res.getWriter().write("{\"success\":false,\"message\":\"" + msg.replace("\"", "'") + "\"}");
    }
}
