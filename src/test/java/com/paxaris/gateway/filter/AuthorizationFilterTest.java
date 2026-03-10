package com.paxaris.gateway.filter;

import com.paxaris.gateway.service.GatewayRoleService;
import com.paxaris.gateway.service.RoleFetchService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.reactive.function.client.WebClient;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthorizationFilterTest {

    private AuthorizationFilter authorizationFilter;
    private RoleFetchService roleFetchService;

    @BeforeEach
    void setUp() {
        WebClient.Builder webClientBuilder = mock(WebClient.Builder.class);
        GatewayRoleService gatewayRoleService = mock(GatewayRoleService.class);
        roleFetchService = mock(RoleFetchService.class);

        authorizationFilter = new AuthorizationFilter(webClientBuilder, gatewayRoleService, roleFetchService);
    }

    @Test
    void filterSkipsAuthForLoginEndpoint() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/identity/login").build()
        );
        GatewayFilterChain chain = mock(GatewayFilterChain.class);
        when(chain.filter(exchange)).thenReturn(reactor.core.publisher.Mono.empty());

        authorizationFilter.filter(exchange, chain).block();

        verify(chain).filter(exchange);
        assertNull(exchange.getResponse().getStatusCode());
    }

    @Test
    void filterReturnsUnauthorizedWhenAuthorizationHeaderMissing() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/project/tasks").build()
        );
        GatewayFilterChain chain = mock(GatewayFilterChain.class);

        authorizationFilter.filter(exchange, chain).block();

        verify(chain, never()).filter(any());
        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
    }

    @Test
    void filterTriggersRoleRefreshForUserMutationPath() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/users").build()
        );
        GatewayFilterChain chain = mock(GatewayFilterChain.class);

        authorizationFilter.filter(exchange, chain).block();

        verify(roleFetchService).fetchRolesDelayed();
        verify(chain, never()).filter(any());
        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
    }
}