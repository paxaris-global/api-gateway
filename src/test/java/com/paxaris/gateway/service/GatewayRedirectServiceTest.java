package com.paxaris.gateway.service;

import org.junit.jupiter.api.Test;
import org.springframework.web.servlet.view.RedirectView;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class GatewayRedirectServiceTest {

    private final GatewayRedirectService gatewayRedirectService = new GatewayRedirectService();

    @Test
    void redirectUserUsesFirstAllowedUrlForKnownToken() {
        String accessToken = "token-123";
        List<String> urls = List.of("http://localhost:4200/dashboard", "http://localhost:4200/projects");

        gatewayRedirectService.receiveTokenUrlsFromIdentityService(accessToken, urls);

        RedirectView redirectView = gatewayRedirectService.redirectUser(accessToken);

        assertEquals("http://localhost:4200/dashboard", redirectView.getUrl());
        assertEquals(urls, gatewayRedirectService.getUrlsForToken(accessToken));
    }

    @Test
    void redirectUserReturnsNoAccessWhenTokenIsUnknown() {
        RedirectView redirectView = gatewayRedirectService.redirectUser("missing-token");

        assertEquals("/error/no-access", redirectView.getUrl());
    }

    @Test
    void receiveTokenUrlsSkipsStorageWhenUrlsAreEmpty() {
        String accessToken = "token-empty";

        gatewayRedirectService.receiveTokenUrlsFromIdentityService(accessToken, List.of());

        assertNull(gatewayRedirectService.getUrlsForToken(accessToken));
    }
}
