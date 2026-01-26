package com.paxaris.gateway.filter;

import com.paxaris.gateway.service.GatewayRoleService;
import com.paxaris.gateway.service.RoleFetchService;
import dto.RealmProductRoleUrl; // Ensure this DTO exists in your source or dependency
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.Ordered;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

@Component
@Slf4j
@RequiredArgsConstructor
public class AuthorizationFilter implements GlobalFilter, Ordered {

    @Value("${IDENTITY_SERVICE_URL}")
    private String identityServiceUrl;

    private final WebClient.Builder webClientBuilder;
    private final GatewayRoleService gatewayRoleService;
    private final RoleFetchService roleFetchService;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        log.info("➡️ [GATEWAY] {} {}", request.getMethod(), path);

        if (path.contains("/login") || path.contains("/signup")) {
            return chain.filter(exchange);
        }

        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = authHeader.substring(7);
        WebClient webClient = webClientBuilder.baseUrl(identityServiceUrl).build();

        return webClient.get()
                .uri("/validate")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                .flatMap(result -> authorize(result, exchange, chain))
                .onErrorResume(e -> {
                    log.error("❌ Validation error: {}", e.getMessage());
                    exchange.getResponse().setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
                    return exchange.getResponse().setComplete();
                });
    }

    private Mono<Void> authorize(Map<String, Object> result, ServerWebExchange exchange, GatewayFilterChain chain) {
        if (!"VALID".equals(result.get("status"))) {
            exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
            return exchange.getResponse().setComplete();
        }

        List<String> roles = (List<String>) result.get("roles");
        String realm = result.get("realm").toString();
        String product = result.get("product").toString();
        String azp = result.get("azp").toString();
        String path = exchange.getRequest().getURI().getPath();

        if ("admin-cli".equals(azp)) {
            return chain.filter(exchange);
        }

        for (String role : roles) {
            List<RealmProductRoleUrl> allowedUrls = gatewayRoleService.getUrls(realm, product, role);
            if (allowedUrls != null) {
                for (RealmProductRoleUrl url : allowedUrls) {
                    if (path.equals(url.getUri())) {
                        return chain.filter(exchange);
                    }
                }
            }
        }

        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
        return exchange.getResponse().setComplete();
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
