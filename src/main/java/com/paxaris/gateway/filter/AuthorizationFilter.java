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
import org.springframework.core.io.buffer.DataBufferUtils;
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

        // Auto-refresh roles cache on key changes
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

        // Skip auth for login/signup endpoints
        if (path.contains("/login") || path.contains("/signup")) {
            return chain.filter(exchange);
        }

        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            return response.setComplete();
        }
        String token = authHeader.substring(7);

        WebClient webClient = webClientBuilder.baseUrl(identityServiceUrl).build();

        return webClient.get()
                .uri("/validate")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {
                })
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

        if (!"VALID".equals(result.get("status"))) {
            response.setStatusCode(HttpStatus.FORBIDDEN);
            return response.setComplete();
        }

        String realm = result.get("realm").toString();
        String product = result.get("product").toString();
        String azp = result.get("azp").toString();

        List<String> roles = ((List<String>) result.get("roles"))
                .stream()
                .map(String::toLowerCase)
                .filter(r -> !IGNORED_ROLES.contains(r))
                .filter(r -> !r.startsWith("default-roles-"))
                .collect(Collectors.toList());

        log.info("🔐 realm={} product={} roles={}", realm, product, roles);

        // FOR IDENTITY API: only forward if user has admin role
        if (path.startsWith("/identity/")) {
            log.info("⏩ Identity API → checking admin role for forwarding");

            boolean isAdmin = roles.stream().anyMatch(role -> role.contains("admin"));

            if (isAdmin) {
                log.info("✅ User has admin role → forwarding to Identity Service");
                return forwardRequestWithBody(exchange, token, identityServiceUrl);
            } else {
                log.warn("⛔ User lacks admin role → access denied to identity API");
                response.setStatusCode(HttpStatus.FORBIDDEN);
                return response.setComplete();
            }
        }

        // Admin-cli token bypass
        if ("admin-cli".equals(azp)) {
            log.info("⏩ admin-cli token → forwarding to backend");
            return forwardRequestWithBody(exchange, token, identityServiceUrl);
        }

        // DB-driven role based URI authorization
        for (String role : roles) {
            List<RealmProductRoleUrl> allowedUrls = gatewayRoleService.getUrls(realm, product, role);
            if (allowedUrls == null) continue;

            for (RealmProductRoleUrl config : allowedUrls) {
                if (path.startsWith(config.getUri())) {
                    String redirectTo = config.getUrl() + path;
                    log.info("✅ ACCESS GRANTED → {} → {}", role, redirectTo);

                    response.setStatusCode(HttpStatus.FOUND);
                    response.getHeaders().setLocation(URI.create(redirectTo));
                    return response.setComplete();
                }
            }
        }

        log.warn("⛔ ACCESS DENIED → {}", path);
        response.setStatusCode(HttpStatus.FORBIDDEN);
        return response.setComplete();
    }

    /**
     * Helper to forward request (with body and headers) to the given base URL
     */
    private Mono<Void> forwardRequestWithBody(ServerWebExchange exchange, String token, String targetBaseUrl) {
        ServerHttpRequest request = exchange.getRequest();
        ServerHttpResponse response = exchange.getResponse();

        // Join request body buffers into a single DataBuffer
        return DataBufferUtils.join(request.getBody())
                .flatMap(dataBuffer -> {
                    byte[] bodyBytes = new byte[dataBuffer.readableByteCount()];
                    dataBuffer.read(bodyBytes);
                    DataBufferUtils.release(dataBuffer);

                    URI targetUri = URI.create(targetBaseUrl + request.getURI().getPath());
                    WebClient webClient = webClientBuilder.build();

                    return webClient.method(request.getMethod())
                            .uri(targetUri)
                            .headers(headers -> {
                                headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + token);
                                // Copy all headers except Host and Content-Length
                                request.getHeaders().forEach((key, values) -> {
                                    if (!key.equalsIgnoreCase(HttpHeaders.HOST) &&
                                            !key.equalsIgnoreCase(HttpHeaders.CONTENT_LENGTH)) {
                                        headers.put(key, values);
                                    }
                                });
                            })
                            .bodyValue(bodyBytes)
                            .exchangeToMono(clientResponse -> {
                                response.setStatusCode(clientResponse.statusCode());
                                clientResponse.headers().asHttpHeaders()
                                        .forEach((key, values) -> response.getHeaders().put(key, values));
                                return response.writeWith(clientResponse.bodyToFlux(org.springframework.core.io.buffer.DataBuffer.class));
                            });
                });
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
