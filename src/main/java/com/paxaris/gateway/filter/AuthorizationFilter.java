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

    private static final Set<String> ADMIN_ROLES = Set.of(
            "manage-realm",
            "manage-users",
            "manage-clients",
            "create-client",
            "impersonation",
            "admin"
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
            log.debug("⏭️ Skipping auth for login/signup endpoint");
            return chain.filter(exchange);
        }

        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("⛔ Missing or invalid Authorization header");
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
                    log.error("❌ Token validation failed for path: {}", path, e);
                    if (e.getMessage() != null && e.getMessage().contains("401")) {
                        response.setStatusCode(HttpStatus.UNAUTHORIZED);
                    } else {
                        response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
                    }
                    return response.setComplete();
                });
    }

    private Mono<Void> handleAuthorization(Map<String, Object> result,
                                           ServerWebExchange exchange,
                                           String token) {

        ServerHttpResponse response = exchange.getResponse();
        String path = exchange.getRequest().getURI().getPath();

        if (!"VALID".equals(result.get("status"))) {
            log.warn("⛔ Token validation returned invalid status: {}", result.get("status"));
            response.setStatusCode(HttpStatus.FORBIDDEN);
            return response.setComplete();
        }

        String realm = result.get("realm") != null ? result.get("realm").toString() : "";
        String product = result.get("product") != null ? result.get("product").toString() : "";
        String azp = result.get("azp") != null ? result.get("azp").toString() : "";

        @SuppressWarnings("unchecked")
        List<String> roles = result.get("roles") != null 
                ? ((List<String>) result.get("roles"))
                    .stream()
                    .map(String::toLowerCase)
                    .filter(r -> !IGNORED_ROLES.contains(r))
                    .filter(r -> !r.startsWith("default-roles-"))
                    .collect(Collectors.toList())
                : List.of();

        log.info("🔐 realm={} product={} roles={}", realm, product, roles);

        // FOR IDENTITY API: only forward if user has admin role
        if (path.startsWith("/identity/")) {
            log.info("⏩ Identity API → checking admin role for forwarding");
            
            boolean isAdmin = isAdminRole(roles);
            
            if (isAdmin) {
                log.info("✅ User has admin role → forwarding to Identity Service");
                return forwardRequestWithBody(exchange, token, identityServiceUrl);
            } else {
                log.warn("⛔ User lacks admin role → access denied to identity API. User roles: {}", roles);
                response.setStatusCode(HttpStatus.FORBIDDEN);
                return response.setComplete();
            }
        }

        // DB-driven role based URI authorization
        // Check each user role against database to see if requested URI is allowed
        for (String role : roles) {
            List<RealmProductRoleUrl> allowedUrls = gatewayRoleService.getUrls(realm, product, role);
            if (allowedUrls == null || allowedUrls.isEmpty()) {
                log.debug("🔍 Role '{}' has no allowed URIs configured", role);
                continue;
            }

            log.debug("🔍 Checking role '{}' with {} allowed URI(s)", role, allowedUrls.size());
            
            // Check if the requested path matches any of the allowed URIs for this role
            for (RealmProductRoleUrl config : allowedUrls) {
                String allowedUri = config.getUri();
                if (allowedUri == null || allowedUri.isEmpty()) {
                    continue;
                }
                
                log.debug("🔍 Comparing requested path '{}' with allowed URI '{}' for role '{}'", 
                        path, allowedUri, role);
                
                // Check if requested path starts with the allowed URI pattern
                if (path.startsWith(allowedUri)) {
                    log.info("✅ URI MATCH FOUND → role='{}' allowedUri='{}' requestedPath='{}'", 
                            role, allowedUri, path);
                    
                    // Build target URL: replace matched URI prefix with target URL
                    String remainingPath = path.substring(allowedUri.length());
                    // Ensure remaining path starts with / if not empty
                    if (!remainingPath.startsWith("/") && !remainingPath.isEmpty()) {
                        remainingPath = "/" + remainingPath;
                    }
                    String targetBaseUrl = config.getUrl();
                    if (targetBaseUrl == null || targetBaseUrl.isEmpty()) {
                        log.error("❌ Target URL is null or empty for role '{}' and URI '{}'", role, allowedUri);
                        continue;
                    }
                    // Remove trailing slash from targetBaseUrl if present
                    if (targetBaseUrl.endsWith("/")) {
                        targetBaseUrl = targetBaseUrl.substring(0, targetBaseUrl.length() - 1);
                    }
                    String fullTargetUrl = targetBaseUrl + remainingPath;
                    
                    log.info("✅ ACCESS GRANTED → role={} matchedUri={} requestedPath={} → forwarding to {}", 
                            role, allowedUri, path, fullTargetUrl);
                    
                    // Forward request with token to the target URL
                    return forwardRequestToFullUrl(exchange, token, fullTargetUrl);
                }
            }
            
            log.debug("❌ Role '{}' does not have access to URI '{}'", role, path);
        }

        log.warn("⛔ ACCESS DENIED → No matching role found for path: {}", path);
        response.setStatusCode(HttpStatus.FORBIDDEN);
        return response.setComplete();
    }

    /**
     * Helper to forward request to a full URL (used for role-based forwarding)
     */
    private Mono<Void> forwardRequestToFullUrl(ServerWebExchange exchange, String token, String fullTargetUrl) {
        ServerHttpRequest request = exchange.getRequest();
        ServerHttpResponse response = exchange.getResponse();

        // Build target URI with query parameters
        String queryString = request.getURI().getQuery();
        URI targetUri = queryString != null && !queryString.isEmpty() 
                ? URI.create(fullTargetUrl + "?" + queryString)
                : URI.create(fullTargetUrl);

        return forwardRequestInternal(exchange, token, targetUri);
    }

    /**
     * Helper to forward request (with body and headers) to the given base URL
     * Appends the request path to the base URL
     */
    private Mono<Void> forwardRequestWithBody(ServerWebExchange exchange, String token, String targetBaseUrl) {
        ServerHttpRequest request = exchange.getRequest();
        ServerHttpResponse response = exchange.getResponse();

        // Build target URI with query parameters
        String queryString = request.getURI().getQuery();
        String targetPath = targetBaseUrl + request.getURI().getPath();
        URI targetUri = queryString != null && !queryString.isEmpty() 
                ? URI.create(targetPath + "?" + queryString)
                : URI.create(targetPath);

        return forwardRequestInternal(exchange, token, targetUri);
    }

    /**
     * Internal method to forward request with proper body handling
     */
    private Mono<Void> forwardRequestInternal(ServerWebExchange exchange, String token, URI targetUri) {
        ServerHttpRequest request = exchange.getRequest();
        ServerHttpResponse response = exchange.getResponse();
        WebClient webClient = webClientBuilder.build();
        
        // Check if request has a body (POST, PUT, PATCH, DELETE)
        boolean hasBody = request.getMethod() == HttpMethod.POST || 
                         request.getMethod() == HttpMethod.PUT || 
                         request.getMethod() == HttpMethod.PATCH ||
                         request.getMethod() == HttpMethod.DELETE;

        if (hasBody) {
            // Join request body buffers into a single DataBuffer
            return DataBufferUtils.join(request.getBody())
                    .flatMap(dataBuffer -> {
                        byte[] bodyBytes = null;
                        if (dataBuffer.readableByteCount() > 0) {
                            bodyBytes = new byte[dataBuffer.readableByteCount()];
                            dataBuffer.read(bodyBytes);
                        }
                        DataBufferUtils.release(dataBuffer);
                        return forwardRequest(webClient, request, response, token, targetUri, bodyBytes);
                    })
                    .onErrorResume(e -> {
                        log.error("❌ Error reading request body for {}", targetUri, e);
                        // Try forwarding without body
                        return forwardRequest(webClient, request, response, token, targetUri, null);
                    });
        } else {
            // No body, forward directly
            return forwardRequest(webClient, request, response, token, targetUri, null);
        }
    }

    /**
     * Core method to forward the HTTP request using WebClient
     */
    private Mono<Void> forwardRequest(WebClient webClient, 
                                     ServerHttpRequest request, 
                                     ServerHttpResponse response, 
                                     String token, 
                                     URI targetUri, 
                                     byte[] bodyBytes) {
        try {
            WebClient.RequestBodySpec requestSpec = webClient.method(request.getMethod())
                    .uri(targetUri)
                    .headers(headers -> {
                        // Set Authorization header with token
                        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + token);
                        
                        // Copy all headers except Host and Content-Length (will be set automatically)
                        request.getHeaders().forEach((key, values) -> {
                            if (!key.equalsIgnoreCase(HttpHeaders.HOST) &&
                                    !key.equalsIgnoreCase(HttpHeaders.CONTENT_LENGTH)) {
                                headers.put(key, values);
                            }
                        });
                    });

            WebClient.RequestHeadersSpec<?> requestSpecWithBody;
            if (bodyBytes != null && bodyBytes.length > 0) {
                requestSpecWithBody = requestSpec.bodyValue(bodyBytes);
            } else {
                requestSpecWithBody = requestSpec;
            }

            return requestSpecWithBody
                    .exchangeToMono(clientResponse -> {
                        // Copy status code
                        response.setStatusCode(clientResponse.statusCode());
                        
                        // Copy response headers (exclude headers that should be set automatically)
                        clientResponse.headers().asHttpHeaders()
                                .forEach((key, values) -> {
                                    String lowerKey = key.toLowerCase();
                                    // Don't copy headers that should be set automatically or cause issues
                                    if (!lowerKey.equals("content-length") &&
                                        !lowerKey.equals("transfer-encoding") &&
                                        !lowerKey.equals("connection") &&
                                        !lowerKey.equals("host")) {
                                        response.getHeaders().put(key, values);
                                    }
                                });
                        
                        // Stream response body directly
                        return response.writeWith(clientResponse.bodyToFlux(org.springframework.core.io.buffer.DataBuffer.class));
                    })
                    .onErrorResume(e -> {
                        log.error("❌ Error forwarding request to {}", targetUri, e);
                        response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
                        return response.setComplete();
                    });
        } catch (Exception e) {
            log.error("❌ Unexpected error forwarding request to {}", targetUri, e);
            response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
            return response.setComplete();
        }
    }

    /**
     * Check if user has admin role
     * Admin roles include: manage-realm, manage-users, manage-clients, create-client, impersonation, or any role containing "admin"
     */
    private boolean isAdminRole(List<String> roles) {
        if (roles == null || roles.isEmpty()) {
            return false;
        }
        return roles.stream()
                .anyMatch(role -> {
                    if (role == null) {
                        return false;
                    }
                    String lowerRole = role.toLowerCase();
                    return ADMIN_ROLES.contains(lowerRole) || lowerRole.contains("admin");
                });
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
