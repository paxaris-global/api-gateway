package com.paxaris.gateway.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.paxaris.gateway.service.GatewayRoleService;
import dto.RealmProductRoleUrl;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
import java.util.*;
import java.util.stream.Collectors;

@Component
@Slf4j
@RequiredArgsConstructor
public class AuthorizationFilter implements GlobalFilter, Ordered {

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

        // Skip auth for open endpoints (login, signup, validate)
        if (path.contains("/login") || path.contains("/signup") || path.contains("/validate")) {
            log.info("🔓 Skipping auth for open endpoint: {}", path);

            // Special handling for /login to enrich response with baseUrls
            if (path.contains("/login")) {
                return handleLoginRequest(exchange);
            }

            return chain.filter(exchange);
        }

        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("❌ Missing or invalid Authorization header");
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            return response.setComplete();
        }

        String token = authHeader.substring(7).trim();
        WebClient webClient = webClientBuilder.baseUrl("http://identity-service:8087").build();

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

    // Handle /login request and enrich response with baseUrls
    private Mono<Void> handleLoginRequest(ServerWebExchange exchange) {
        ServerHttpRequest request = exchange.getRequest();
        ServerHttpResponse response = exchange.getResponse();
        WebClient webClient = webClientBuilder.baseUrl("http://identity-service:8087").build();

        // Read request body
        Mono<byte[]> bodyMono = DataBufferUtils.join(request.getBody())
                .map(dataBuffer -> {
                    byte[] bytes = new byte[dataBuffer.readableByteCount()];
                    dataBuffer.read(bytes);
                    DataBufferUtils.release(dataBuffer);
                    return bytes;
                })
                .defaultIfEmpty(new byte[0]);

        return bodyMono.flatMap(bodyBytes -> {
            // Preserve original Content-Type
            String contentTypeHeader = request.getHeaders().getFirst(HttpHeaders.CONTENT_TYPE);
            MediaType contentType = contentTypeHeader != null ? MediaType.parseMediaType(contentTypeHeader) : MediaType.APPLICATION_JSON;

            WebClient.RequestBodySpec requestSpec = webClient.method(request.getMethod())
                    .uri("/login")
                    .headers(h -> request.getHeaders().forEach((k, v) -> h.put(k, v)))
                    .contentType(contentType)
                    .bodyValue(bodyBytes);

            return requestSpec.retrieve()
                    .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                    .flatMap(identityResponse -> {
                        try {
                            // Extract realm, product, roles from Identity Service response
                            String realm = identityResponse.getOrDefault("realm", "").toString();
                            String product = identityResponse.getOrDefault("product", "").toString();
                            List<String> roles = (List<String>) identityResponse.getOrDefault("roles", List.of());

                            // Fetch base URLs from GatewayRoleService.memory
                            List<String> baseUrls = roles.stream()
                                    .flatMap(role -> gatewayRoleService.getUrls(realm, product, role).stream())
                                    .map(RealmProductRoleUrl::getUrl)
                                    .distinct()
                                    .collect(Collectors.toList());

                            // Add baseUrls to response
                            identityResponse.put("baseUrls", baseUrls);

                            byte[] finalResponse = objectMapper.writeValueAsBytes(identityResponse);
                            response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
                            response.setStatusCode(HttpStatus.OK);
                            return response.writeWith(Mono.just(response.bufferFactory().wrap(finalResponse)));
                        } catch (Exception e) {
                            log.error("💥 Failed to enrich login response with baseUrls", e);
                            response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
                            return response.setComplete();
                        }
                    });
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
        log.info("🔹 Token validated. Realm: {}, Product: {}, Roles: {}", realm, product, roles);

        // Adjust path to match downstream service (strip /keycloak)
        String adjustedPath = path.replaceFirst("/keycloak", "");

        // Roles allowed to forward directly
        List<String> allowedRoles = List.of(
                "admin",
                "manage-users",
                "manage-realm",
                "create-client",
                "impersonation",
                "manage-account",
                "view-profile",
                "admin-client",
                "realm-admin"
        );

        boolean isAdmin = roles.stream().anyMatch(allowedRoles::contains);
        if (isAdmin) {
            log.info("👑 Admin/allowed role detected, forwarding request to Identity Service");
            return forwardRequest(exchange, "http://identity-service:8087" + adjustedPath, token);
        }

        // Check other roles for URL access
        boolean allowed = false;
        RealmProductRoleUrl matchedUrl = null;
        for (String role : roles) {
            List<RealmProductRoleUrl> urls = gatewayRoleService.getUrls(realm, product, role);
            if (urls == null) continue;
            for (RealmProductRoleUrl url : urls) {
                if (url.getUri() != null && adjustedPath.equals(url.getUri())) {
                    allowed = true;
                    matchedUrl = url;
                    break;
                }
            }
            if (allowed) break;
        }

        if (allowed && matchedUrl != null) {
            String redirectTo = matchedUrl.getUrl() + matchedUrl.getUri();
            log.info("🚀 Redirecting to downstream service: {}", redirectTo);
            response.setStatusCode(HttpStatus.FOUND);
            response.getHeaders().setLocation(URI.create(redirectTo));
            return response.setComplete();
        }

        log.warn("❌ Access denied for URL: {}", path);
        response.setStatusCode(HttpStatus.FORBIDDEN);
        return response.setComplete();
    }

    private Mono<Void> forwardRequest(ServerWebExchange exchange, String targetUrl, String token) {
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
            WebClient.RequestBodySpec requestSpec = webClient.method(method)
                    .uri(targetUrl)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .headers(h -> request.getHeaders().forEach((k, v) -> h.put(k, v)));

            if (method == HttpMethod.POST || method == HttpMethod.PUT) {
                requestSpec.contentType(MediaType.APPLICATION_JSON).bodyValue(bodyBytes);
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
                values.forEach(value -> curl.append(" \\\n  -H '").append(key).append(": ").append(value).append("'"))
        );

        return curl.toString();
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
