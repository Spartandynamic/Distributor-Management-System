package com.spartan.dms.controller;

import com.spartan.dms.dto.ApiResponse;
import com.spartan.dms.entity.Distributor;
import com.spartan.dms.entity.User;
import com.spartan.dms.security.SecurityUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/*
 * Staff portal "indha DP DMS la yaaru?" nu kekka.
 * Portal idha vechu distributorId edukkum (bill / shop create ku venum).
 */
@RestController
@RequestMapping("/api/v1/integration/portal")
@RequiredArgsConstructor
public class PortalIntegrationController {

    private final SecurityUtils securityUtils;

    @PreAuthorize("hasRole('DISTRIBUTOR')")
    @GetMapping("/me")
    public ResponseEntity<ApiResponse<Map<String, Object>>> me() {
        User u = securityUtils.getCurrentUser();
        Distributor d = u.getDistributor();
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("username", u.getUsername());
        m.put("fullName", u.getFullName());
        m.put("distributorId", d != null ? d.getId() : null);
        m.put("distributorName", d != null ? d.getDistributorName() : null);
        m.put("superStockistName", d != null && d.getSuperStockist() != null ? d.getSuperStockist().getSuperStockistName() : null);
        return ResponseEntity.ok(ApiResponse.<Map<String, Object>>builder()
                .success(true).message("OK").data(m).build());
    }
}
