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

        // Skip auth for open endpoints (login, signup, validate) (changed)
        if (path.contains("/login") || path.contains("/signup") || path.contains("/validate")) {  // (changed)
            log.info("🔓 Skipping auth for open endpoint: {}", path); // (changed)

            // Special handling for /login to enrich response with baseUrls (changed)
            if (path.contains("/login")) {  // (changed)
                return handleLoginRequest(exchange); // (changed)
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

    // (changed) Handle login request and enrich with baseUrls
    private Mono<Void> handleLoginRequest(ServerWebExchange exchange) { // (changed)
        ServerHttpRequest request = exchange.getRequest(); // (changed)
        ServerHttpResponse response = exchange.getResponse(); // (changed)
        WebClient webClient = webClientBuilder.baseUrl("http://identity-service:8087").build(); // (changed)

        Mono<byte[]> bodyMono = DataBufferUtils.join(request.getBody()) // (changed)
                .map(dataBuffer -> { // (changed)
                    byte[] bytes = new byte[dataBuffer.readableByteCount()]; // (changed)
                    dataBuffer.read(bytes); // (changed)
                    DataBufferUtils.release(dataBuffer); // (changed)
                    return bytes; // (changed)
                }) // (changed)
                .defaultIfEmpty(new byte[0]); // (changed)

        return bodyMono.flatMap(bodyBytes -> { // (changed)
            WebClient.RequestHeadersSpec<?> requestSpec; // (changed)

            if (request.getMethod() == HttpMethod.POST || request.getMethod() == HttpMethod.PUT) { // (changed)
                requestSpec = webClient.method(request.getMethod()) // (changed)
                        .uri("/login") // (changed)
                        .headers(h -> request.getHeaders().forEach((k, v) -> h.put(k, v))) // (changed)
                        .contentType(MediaType.APPLICATION_JSON) // (changed)
                        .bodyValue(bodyBytes); // (changed)
            } else { // GET or other methods (changed)
                requestSpec = webClient.method(request.getMethod()) // (changed)
                        .uri("/login") // (changed)
                        .headers(h -> request.getHeaders().forEach((k, v) -> h.put(k, v))); // (changed)
            }

            return requestSpec.retrieve() // (changed)
                    .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {}) // (changed)
                    .flatMap(identityResponse -> { // (changed)
                        try { // (changed)
                            String realm = identityResponse.getOrDefault("realm", "").toString(); // (changed)
                            String product = identityResponse.getOrDefault("product", "").toString(); // (changed)
                            List<String> roles = (List<String>) identityResponse.getOrDefault("roles", List.of()); // (changed)

                            List<String> baseUrls = roles.stream() // (changed)
                                    .flatMap(role -> gatewayRoleService.getUrls(realm, product, role).stream()) // (changed)
                                    .map(RealmProductRoleUrl::getUrl) // (changed)
                                    .distinct() // (changed)
                                    .collect(Collectors.toList()); // (changed)

                            identityResponse.put("baseUrls", baseUrls); // (changed)

                            byte[] finalResponse = objectMapper.writeValueAsBytes(identityResponse); // (changed)
                            response.getHeaders().setContentType(MediaType.APPLICATION_JSON); // (changed)
                            response.setStatusCode(HttpStatus.OK); // (changed)
                            return response.writeWith(Mono.just(response.bufferFactory().wrap(finalResponse))); // (changed)
                        } catch (Exception e) { // (changed)
                            log.error("💥 Failed to enrich login response with baseUrls", e); // (changed)
                            response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR); // (changed)
                            return response.setComplete(); // (changed)
                        } // (changed)
                    }); // (changed)
        }); // (changed)
    } // (changed)

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
                "admin", "manage-users", "manage-realm", "create-client",
                "impersonation", "manage-account", "view-profile",
                "admin-client", "realm-admin"
        );

        boolean isAdmin = roles.stream().anyMatch(allowedRoles::contains);

        if (isAdmin) {
            log.info("👑 Admin/allowed role detected, forwarding request to Identity Service");
            return forwardRequest(exchange, "http://identity-service:8087" + adjustedPath, token);
        }

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
            WebClient.RequestHeadersSpec<?> requestSpec;

            if (method == HttpMethod.POST || method == HttpMethod.PUT) {
                requestSpec = webClient.method(method)
                        .uri(targetUrl)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .headers(h -> request.getHeaders().forEach((k, v) -> h.put(k, v)))
                        .contentType(MediaType.APPLICATION_JSON)
                        .bodyValue(bodyBytes);
            } else {
                requestSpec = webClient.method(method)
                        .uri(targetUrl)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .headers(h -> request.getHeaders().forEach((k, v) -> h.put(k, v)));
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
