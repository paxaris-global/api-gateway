package com.paxaris.gateway.service;

import dto.RealmProductRole;
import dto.RealmProductRoleUrl;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GatewayRoleServiceTest {

    private final GatewayRoleService gatewayRoleService = new GatewayRoleService();

    @Test
    void loadRolesAndGetUrlsForExactProduct() {
        RealmProductRoleUrl url = RealmProductRoleUrl.builder()
                .uri("/projects")
                .url("http://service")
                .httpMethod("GET")
                .build();

        RealmProductRole role = RealmProductRole.builder()
                .realmName("demo")
                .productName("pm")
                .roleName("admin")
                .urls(List.of(url))
                .build();

        gatewayRoleService.loadRoles(List.of(role));

        List<RealmProductRoleUrl> result = gatewayRoleService.getUrls("demo", "pm", "admin");
        assertEquals(1, result.size());
        assertEquals("/projects", result.getFirst().getUri());
        assertEquals("GET", result.getFirst().getHttpMethod());
    }

    @Test
    void getUrlsFallsBackWhenProductMissing() {
        RealmProductRoleUrl url = RealmProductRoleUrl.builder()
                .uri("/dashboard")
                .url("http://service")
                .httpMethod("POST")
                .build();

        RealmProductRole role = RealmProductRole.builder()
                .realmName("demo")
                .productName("analytics")
                .roleName("editor")
                .urls(List.of(url))
                .build();

        gatewayRoleService.loadRoles(List.of(role));

        List<RealmProductRoleUrl> fallbackResult = gatewayRoleService.getUrls("demo", "", "editor");
        assertEquals(1, fallbackResult.size());
        assertEquals("/dashboard", fallbackResult.getFirst().getUri());
    }

    @Test
    void loadRolesHandlesNullInput() {
        gatewayRoleService.loadRoles(null);
        assertTrue(gatewayRoleService.getMemory().isEmpty());
    }
}
