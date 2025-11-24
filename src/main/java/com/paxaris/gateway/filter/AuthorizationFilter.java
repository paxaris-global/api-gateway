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
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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

        if (path.contains("/login") || path.contains("/signup") || path.contains("/validate")) {
            log.info("🔓 Skipping auth for open endpoint: {}", path);

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
                    log.error("💥 [GATEWAY] Identity Service validation failed", e);
                    response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
                    return response.setComplete();
                });
    }

    private Mono<Void> handleLoginRequest(ServerWebExchange exchange) {
        ServerHttpRequest request = exchange.getRequest();
        ServerHttpResponse response = exchange.getResponse();
        WebClient webClient = webClientBuilder.baseUrl("http://identity-service:8087").build();

        // Read body safely as bytes
        return DataBufferUtils.join(request.getBody())
                .map(dataBuffer -> {
                    byte[] bytes = new byte[dataBuffer.readableByteCount()];
                    dataBuffer.read(bytes);
                    DataBufferUtils.release(dataBuffer);
                    return bytes;
                })
                .defaultIfEmpty(new byte[0])
                .flatMap(bodyBytes -> {
                    String bodyStr = new String(bodyBytes, StandardCharsets.UTF_8);
                    log.info("📦 Login request body: {}", bodyStr);

                    WebClient.RequestBodySpec requestSpec = webClient.method(request.getMethod())
                            .uri("/login")
                            .headers(h -> request.getHeaders().forEach((k, v) -> h.addAll(k, v)))
                            .contentType(MediaType.APPLICATION_JSON);

                    if (request.getMethod() == HttpMethod.POST || request.getMethod() == HttpMethod.PUT) {
                        requestSpec.bodyValue(bodyStr);
                    }

                    return requestSpec.retrieve()
                            .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                            .flatMap(identityResponse -> {
                                try {
                                    String realm = identityResponse.getOrDefault("realm", "").toString();
                                    String product = identityResponse.getOrDefault("product", "").toString();
                                    List<String> roles = (List<String>) identityResponse.getOrDefault("roles", List.of());

                                    // Build productUrls
                                    List<Map<String, Object>> productUrls = roles.stream()
                                            .flatMap(roleStr -> {
                                                List<RealmProductRoleUrl> urls = gatewayRoleService.getUrls(realm, product, roleStr);
                                                if (urls == null) return List.<Map<String, Object>>of().stream();
                                                return urls.stream().map(url -> {
                                                    Map<String, Object> map = new HashMap<>();
                                                    map.put("url", url.getUrl() + url.getUri());
                                                    map.put("baseUrl", url.getUrl());
                                                    map.put("uri", url.getUri());
                                                    map.put("role", roleStr);
                                                    return map;
                                                });
                                            })
                                            .collect(Collectors.toList());

                                    identityResponse.put("productUrls", productUrls);

                                    byte[] finalResponse = objectMapper.writeValueAsBytes(identityResponse);
                                    response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
                                    response.setStatusCode(HttpStatus.OK);
                                    return response.writeWith(Mono.just(response.bufferFactory().wrap(finalResponse)));
                                } catch (Exception e) {
                                    log.error("💥 Failed to enrich login response", e);
                                    response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
                                    return response.setComplete();
                                }
                            })
                            .onErrorResume(e -> {
                                log.error("💥 Error calling Identity Service", e);
                                response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
                                return response.setComplete();
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

        String adjustedPath = path.replaceFirst("/keycloak", "");

        List<String> allowedRoles = List.of(
                "admin", "manage-users", "manage-realm", "create-client", "impersonation",
                "manage-account", "view-profile", "admin-client", "realm-admin"
        );

        boolean isAdmin = roles.stream().anyMatch(allowedRoles::contains);

        if (isAdmin) {
            log.info("👑 Admin/allowed role detected, forwarding request to Identity Service");
            return forwardRequest(exchange, "http://identity-service:8087" + adjustedPath, token);
        }

        boolean allowed = false;
        RealmProductRoleUrl matchedUrl = null;
        outer:
        for (String roleStr : roles) {
            List<RealmProductRoleUrl> urls = gatewayRoleService.getUrls(realm, product, roleStr);
            if (urls == null) continue;
            for (RealmProductRoleUrl url : urls) {
                if (url.getUri() != null && adjustedPath.equals(url.getUri())) {
                    allowed = true;
                    matchedUrl = url;
                    break outer;
                }
            }
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

        return DataBufferUtils.join(request.getBody())
                .map(dataBuffer -> {
                    byte[] bytes = new byte[dataBuffer.readableByteCount()];
                    dataBuffer.read(bytes);
                    DataBufferUtils.release(dataBuffer);
                    return bytes;
                })
                .defaultIfEmpty(new byte[0])
                .flatMap(bodyBytes -> {
                    WebClient.RequestBodySpec requestSpec = webClient.method(method)
                            .uri(targetUrl)
                            .headers(h -> request.getHeaders().forEach((k, v) -> h.addAll(k, v)));

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

    @Override
    public int getOrder() {
        return -1;
    }
}
