package com.spartan.dms.controller;

import com.spartan.dms.dto.ApiResponse;
import com.spartan.dms.dto.ForgotPasswordRequest;
import com.spartan.dms.dto.LoginRequest;
import com.spartan.dms.dto.LoginResponse;
import com.spartan.dms.dto.RegisterRequest;
import com.spartan.dms.dto.ResetPasswordRequest;
import com.spartan.dms.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class AuthController {

    private final AuthService authService;
    private final com.spartan.dms.security.SecurityUtils securityUtils;
    private final com.spartan.dms.service.AuditLogService auditLogService;
    private final com.spartan.dms.security.JwtUtil jwtUtil;
    private final com.spartan.dms.security.TokenRevocationService tokenRevocationService;

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<String>> register(
            @Valid @RequestBody RegisterRequest request) {

        ApiResponse<String> response = authService.register(request);

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<ApiResponse<String>> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest request) {

        return ResponseEntity.ok(authService.forgotPassword(request));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<ApiResponse<String>> resetPassword(
            @Valid @RequestBody ResetPasswordRequest request) {

        return ResponseEntity.ok(authService.resetPassword(request));
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponse>> login(
            @RequestBody LoginRequest request) {

        ApiResponse<LoginResponse> response = authService.login(request);

        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<String>> logout(jakarta.servlet.http.HttpServletRequest request) {

        try {
            var user = securityUtils.getCurrentUser();
            auditLogService.logAs("LOGOUT", "AUTH", user.getId(), user.getUsername(), user.getRole().getRoleName(), "Logout");
            // Revoke ONLY the token used for this request. (Previously every
            // token of the account was invalidated, so one logout on any
            // device kicked all other admin sessions out with "Session expired".)
            String header = request.getHeader(com.spartan.dms.constants.SecurityConstants.HEADER);
            if (header != null && header.startsWith(com.spartan.dms.constants.SecurityConstants.TOKEN_PREFIX)) {
                String token = header.substring(com.spartan.dms.constants.SecurityConstants.TOKEN_PREFIX.length());
                tokenRevocationService.revoke(token, jwtUtil.extractExpirationMillis(token));
            }
        } catch (Exception ignored) {
            // No authenticated context (e.g. token already expired) — logout still succeeds client-side.
        }

        return ResponseEntity.ok(
                ApiResponse.success(
                        "Logout Successful",
                        "User Logged Out Successfully"
                )
        );
    }

    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return new ResponseEntity<>("DMS Authentication Service Running", HttpStatus.OK);
    }
}