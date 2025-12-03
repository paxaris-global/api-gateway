package com.paxaris.gateway.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.paxaris.gateway.service.GatewayRoleService;
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
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.core.io.buffer.DataBufferUtils;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

@Component
@Slf4j
@RequiredArgsConstructor
public class AuthorizationFilter implements GlobalFilter, Ordered {

    @Value("${IDENTITY_SERVICE_URL}")
    private String identityServiceUrl;

    @Value("${KEYCLOAK_BASE_URL}")
    private String keycloakBaseUrl;

    // UPDATED ↓
    @Value("${PROJECT_MANAGEMENT_BASE_URL}")             // UPDATED
    private String projectManagerBaseUrl;             // UPDATED (used by RoleFetchService)

    private final WebClient.Builder webClientBuilder;
    private final GatewayRoleService gatewayRoleService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        ServerHttpResponse response = exchange.getResponse();
        String path = request.getURI().getPath();

        log.info("➡️ [GATEWAY] Incoming request: {} {}", request.getMethod(), path);
        log.info("📟 [CURL] Equivalent command:\n{}", buildCurlCommand(request));

        // Skip login & signup
        if (path.contains("/login") || path.contains("/signup")) {
            log.info("🔓 Skipping auth for open endpoint: {}", path);
            return chain.filter(exchange);
        }

        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("❌ Missing or invalid Authorization header");
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            return response.setComplete();
        }

        String token = authHeader.substring(7).trim();
        WebClient webClient = webClientBuilder.baseUrl(identityServiceUrl).build();

        return webClient.get()
                .uri("/validate")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                .flatMap(result -> handleValidationResponse(result, path, response, exchange, token))
                .onErrorResume(e -> {
                    log.error("💥 [GATEWAY] Identity Service validation failed: {}", e.getMessage(), e);
                    response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
                    return response.setComplete();
                });
    }

    private Mono<Void> handleValidationResponse(Map<String, Object> result, String path,
                                                ServerHttpResponse response, ServerWebExchange exchange,
                                                String token) {

        if (!"VALID".equals(result.get("status"))) {
            log.warn("❌ Token invalid for URL: {}", path);
            response.setStatusCode(HttpStatus.FORBIDDEN);
            return response.setComplete();
        }

        String realm = result.getOrDefault("realm", "").toString();
        String product = result.getOrDefault("product", "").toString();
        List<String> roles = (List<String>) result.getOrDefault("roles", List.of());
        String azp = result.getOrDefault("azp", "").toString();

        log.info("🔹 Token validated. Realm: {}, Product: {}, Roles: {}, azp: {}", realm, product, roles, azp);

        // Master token shortcut
        if ("admin-cli".equals(azp)) {
            log.info("👑 Master token detected, forwarding request to Identity Service");
            return forwardRequest(exchange, identityServiceUrl, token);
        }

        // Admin rule
        if (path.matches("^/identity/[^/]+/admin/.*")) {
            log.warn("⛔ Admin access denied: {}", path);
            response.setStatusCode(HttpStatus.FORBIDDEN);
            return response.setComplete();
        }

        String adjustedPath = path.replaceFirst("/identity", "");

        // Allowed system roles
        List<String> allowedRoles = List.of(
                "admin", "manage-users", "manage-realm", "create-client",
                "impersonation", "manage-account", "view-profile"
        );

        if (roles.stream().anyMatch(allowedRoles::contains)) {
            log.info("👑 System role detected, forwarding to Identity Service");
            return forwardRequest(exchange, identityServiceUrl, token);
        }

        // Role → URL resolution
        for (String role : roles) {
            List<RealmProductRoleUrl> urls = gatewayRoleService.getUrls(realm, product, role);
            if (urls == null) continue;

            for (RealmProductRoleUrl url : urls) {
                if (adjustedPath.equals(url.getUri())) {

                    // UPDATED ↓
                    String redirectTo = url.getUrl() + url.getUri();  // UPDATED
                    log.info("🚀 Redirecting to downstream service: {}", redirectTo);
                    response.setStatusCode(HttpStatus.FOUND);
                    response.getHeaders().setLocation(URI.create(redirectTo));
                    return response.setComplete();
                }
            }
        }

        log.warn("❌ Access denied for URL: {}", path);
        response.setStatusCode(HttpStatus.FORBIDDEN);
        return response.setComplete();
    }

    private Mono<Void> forwardRequest(ServerWebExchange exchange, String targetBaseUrl, String token) {
        ServerHttpRequest request = exchange.getRequest();
        ServerHttpResponse response = exchange.getResponse();

        WebClient webClient = webClientBuilder.build();
        HttpMethod method = request.getMethod();

        Mono<byte[]> bodyMono = DataBufferUtils.join(request.getBody())
                .map(dataBuffer -> {
                    byte[] bytes = new byte[dataBuffer.readableByteCount()];
                    dataBuffer.read(bytes);
                    DataBufferUtils.release(dataBuffer);
                    return bytes;
                })
                .defaultIfEmpty(new byte[0]);

        return bodyMono.flatMap(bodyBytes -> {
            String path = request.getURI().getPath();
            String query = request.getURI().getQuery();
            String forwardUrl = targetBaseUrl.replaceAll("/$", "") + path +
                    (query != null ? "?" + query : "");

            log.info("➡️ [GATEWAY] Forwarding request to URL: {}", forwardUrl);
            log.info("🔑 [GATEWAY] Forwarding Authorization header: Bearer {}", token);

            WebClient.RequestBodySpec requestSpec = webClient.method(method)
                    .uri(forwardUrl)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token);

            if (method == HttpMethod.POST || method == HttpMethod.PUT) {
                requestSpec.contentType(MediaType.APPLICATION_JSON)
                        .bodyValue(bodyBytes);
            }

            return requestSpec.exchangeToMono(clientResponse -> {
                response.setStatusCode(clientResponse.statusCode());
                response.getHeaders().addAll(clientResponse.headers().asHttpHeaders());
                return clientResponse.bodyToMono(byte[].class)
                        .flatMap(body -> response.writeWith(Mono.just(response.bufferFactory().wrap(body))));
            });
        });
    }

    private String buildCurlCommand(ServerHttpRequest request) {
        StringBuilder curl = new StringBuilder("curl -X ")
                .append(request.getMethod())
                .append(" '")
                .append(request.getURI())
                .append("'");

        request.getHeaders().forEach((key, values) ->
                values.forEach(value ->
                        curl.append(" \\\n  -H '").append(key).append(": ").append(value).append("'"))
        );
        return curl.toString();
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
