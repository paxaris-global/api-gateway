package com.paxaris.gateway.filter;

import com.paxaris.gateway.service.GatewayRoleService;
import com.paxaris.gateway.service.RoleFetchService;
import dto.RealmProductRoleUrl;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.Ordered;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Component
@Slf4j
@RequiredArgsConstructor
public class AuthorizationFilter implements GlobalFilter, Ordered {

    @Value("${IDENTITY_SERVICE_URL}")
    private String identityServiceUrl;

    private final WebClient.Builder webClientBuilder;
    private final GatewayRoleService gatewayRoleService;
    private final RoleFetchService roleFetchService;

    // Keycloak system roles to ignore for URI auth
    private static final Set<String> IGNORED_ROLES = Set.of(
            "offline_access",
            "uma_authorization",
            "manage-account",
            "manage-account-links",
            "view-profile"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        ServerHttpRequest request = exchange.getRequest();
        ServerHttpResponse response = exchange.getResponse();
        String path = request.getURI().getPath();

        log.info("➡️ [GATEWAY] {} {}", request.getMethod(), path);

        // Auto-refresh role cache on POST/PUT/DELETE to key endpoints
        if (request.getMethod() == HttpMethod.POST ||
            request.getMethod() == HttpMethod.PUT ||
            request.getMethod() == HttpMethod.DELETE) {

            if (path.contains("/signup") ||
                path.contains("/users") ||
                path.contains("/clients") ||
                path.contains("/roles")) {

                log.info("🟡 Role config changed → refreshing gateway roles");
                roleFetchService.fetchRolesDelayed();
            }
        }

        // Skip auth for login/signup endpoints (allow direct forwarding)
        if (path.contains("/login") || path.contains("/signup")) {
            return chain.filter(exchange);
        }

        // Extract Bearer token
        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            return response.setComplete();
        }
        String token = authHeader.substring(7);

        // Call Identity Service /validate endpoint with token
        WebClient webClient = webClientBuilder.baseUrl(identityServiceUrl).build();

        return webClient.get()
                .uri("/validate")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                .flatMap(result -> handleAuthorization(result, exchange, token))
                .onErrorResume(e -> {
                    log.error("❌ Validation failed", e);
                    response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
                    return response.setComplete();
                });
    }

    private Mono<Void> handleAuthorization(Map<String, Object> result,
                                           ServerWebExchange exchange,
                                           String token) {

        ServerHttpResponse response = exchange.getResponse();
        String path = exchange.getRequest().getURI().getPath();

        // Token validation failed
        if (!"VALID".equals(result.get("status"))) {
            response.setStatusCode(HttpStatus.FORBIDDEN);
            return response.setComplete();
        }

        // If identity service API, forward request directly to Identity Service
        if (path.startsWith("/identity/")) {
            log.info("⏩ Identity API → forwarding to Identity Service");
            return forward(exchange, token);
        }

        // Extract needed info from validation response
        String realm = result.get("realm").toString();
        String product = result.get("product").toString();
        String azp = result.get("azp").toString();

        // Get roles and filter out ignored roles
        List<String> roles = ((List<String>) result.get("roles"))
                .stream()
                .map(String::toLowerCase)
                .filter(r -> !IGNORED_ROLES.contains(r))
                .filter(r -> !r.startsWith("default-roles-"))
                .collect(Collectors.toList());

        log.info("🔐 realm={} product={} roles={}", realm, product, roles);

        // Allow admin-cli master token to forward request without restriction
        if ("admin-cli".equals(azp)) {
            return forward(exchange, token);
        }

        // Check allowed URLs based on roles from DB/cache
        for (String role : roles) {
            List<RealmProductRoleUrl> allowedUrls = gatewayRoleService.getUrls(realm, product, role);
            if (allowedUrls == null) continue;

            for (RealmProductRoleUrl config : allowedUrls) {
                // Prefix match is critical to allow partial matching on URI
                if (path.startsWith(config.getUri())) {
                    String redirectTo = config.getUrl() + path;
                    log.info("✅ ACCESS GRANTED → {} → {}", role, redirectTo);

                    response.setStatusCode(HttpStatus.FOUND);
                    response.getHeaders().setLocation(URI.create(redirectTo));
                    return response.setComplete();
                }
            }
        }

        // No matching allowed URL found for roles → deny access
        log.warn("⛔ ACCESS DENIED → {}", path);
        response.setStatusCode(HttpStatus.FORBIDDEN);
        return response.setComplete();
    }

    private Mono<Void> forward(ServerWebExchange exchange, String token) {
        ServerHttpRequest request = exchange.getRequest();
        ServerHttpResponse response = exchange.getResponse();

        WebClient webClient = webClientBuilder.build();

        // Forward the request to the original URI with Authorization header
        return webClient.method(request.getMethod())
                .uri(request.getURI())
                .headers(headers -> headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .exchangeToMono(clientResponse -> {
                    response.setStatusCode(clientResponse.statusCode());
                    response.getHeaders().addAll(clientResponse.headers().asHttpHeaders());
                    return response.writeWith(clientResponse.bodyToFlux(byte[].class)
                            .map(bytes -> response.bufferFactory().wrap(bytes)));
                });
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
