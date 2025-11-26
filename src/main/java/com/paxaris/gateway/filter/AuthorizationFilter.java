package com.paxaris.gateway.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.paxaris.gateway.service.GatewayRoleService;
import dto.RealmProductRoleUrl;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
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
import java.nio.charset.StandardCharsets;
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
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        ServerHttpResponse response = exchange.getResponse();
        String path = request.getURI().getPath();

        log.info("➡️ [GATEWAY] Incoming request: {} {}", request.getMethod(), path);
        log.info("📟 [CURL] Equivalent command:\n{}", buildCurlCommand(request));

        // Skip auth for open endpoints
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
        String azp = result.getOrDefault("azp", "").toString(); // <-- NEW: capture azp
        log.info("🔹 Token validated. Realm: {}, Product: {}, Roles: {}, azp: {}", realm, product, roles, azp);

        String adjustedPath = path.replaceFirst("/identity", "");

        // -----------------------------
        // NEW: Allow master token if azp == admin-cli
        // -----------------------------
        if ("admin-cli".equals(azp)) { // <-- NEW: master token bypass
            log.info("👑 Master token detected (azp=admin-cli), forwarding request to Identity Service");
            return forwardRequest(exchange, identityServiceUrl, token);
        }

        // -----------------------------
        // EXISTING: User token handling
        // -----------------------------
        List<String> allowedRoles = List.of(
                "admin",
                "manage-users",
                "manage-realm",
                "create-client",
                "impersonation",
                "manage-account",
                "view-profile"
        );
        boolean hasAllowedRole = roles.stream().anyMatch(allowedRoles::contains);

        if (hasAllowedRole) {
            log.info("👑 User token with allowed roles, forwarding request to Identity Service");
            return forwardRequest(exchange, identityServiceUrl, token);
        }

        // -----------------------------
        // EXISTING: Role-based URL mapping check for user tokens
        // -----------------------------
        for (String role : roles) {
            List<RealmProductRoleUrl> urls = gatewayRoleService.getUrls(realm, product, role);
            if (urls == null) continue;
            for (RealmProductRoleUrl url : urls) {
                if (adjustedPath.equals(url.getUri())) {
                    String redirectTo = url.getUrl() + url.getUri();
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
            String path = request.getURI().getPath();
            String query = request.getURI().getQuery();
            String forwardUrl = targetUrl.replaceAll("/$", "") + path + (query != null ? "?" + query : "");

            // LOG THE FORWARD URL
            log.info("➡️ [GATEWAY] Forwarding request to URL: {}", forwardUrl);

            // LOG THE REQUEST BODY
            if (bodyBytes.length > 0) {
                try {
                    String bodyString = new String(bodyBytes, StandardCharsets.UTF_8);
                    // Try to pretty-print JSON if possible
                    if (bodyString.trim().startsWith("{") || bodyString.trim().startsWith("[")) {
                        Object json = objectMapper.readValue(bodyString, Object.class);
                        String prettyJson = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(json);
                        log.info("📦 [GATEWAY] Forwarding request body:\n{}", prettyJson);
                    } else {
                        log.info("📦 [GATEWAY] Forwarding request body: {}", bodyString);
                    }
                } catch (Exception e) {
                    log.warn("⚠️ Failed to parse request body for logging, logging raw bytes", e);
                    log.info("📦 [GATEWAY] Forwarding request body (raw): {}", new String(bodyBytes, StandardCharsets.UTF_8));
                }
            } else {
                log.info("📦 [GATEWAY] No request body to forward");
            }

            WebClient.RequestBodySpec requestSpec = webClient.method(method)
                    .uri(forwardUrl)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .headers(h -> h.addAll(request.getHeaders())); // safer header forwarding

            if (method == HttpMethod.POST || method == HttpMethod.PUT) {
                requestSpec.contentType(MediaType.APPLICATION_JSON)
                        .bodyValue(bodyBytes); // forward raw bytes
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
