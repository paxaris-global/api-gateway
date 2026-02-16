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

                            log.info("🔄 Role config changed → refreshing gateway roles");
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
                .flatMap(result -> handleAuthorization(result, exchange, token, chain))
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
                                           String token,
                                           GatewayFilterChain chain) {

        ServerHttpResponse response = exchange.getResponse();
        String path = exchange.getRequest().getURI().getPath();

        // ================= Token validation =================
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

        // ================= Identity service admin access =================
        if (path.startsWith("/identity/")) {
            log.info("⏩ Identity API → checking admin role");

            if (isAdminRole(roles)) {
                String fullTargetUrl = identityServiceUrl.endsWith("/")
                        ? identityServiceUrl.substring(0, identityServiceUrl.length() - 1) + path
                        : identityServiceUrl + path;

//                return forwardRequest(exchange, token, fullTargetUrl);
                return chain.filter(exchange);
            } else {
                log.warn("⛔ Access denied to Identity API. Roles={}", roles);
                response.setStatusCode(HttpStatus.FORBIDDEN);
                return response.setComplete();
            }
        }

        // ================= Project Service Admin Access =================
        // Allow Admins to access Project Manager endpoints (like save-or-update)
        if (path.startsWith("/project/") && isAdminRole(roles)) {
            log.info("⏩ Project API → Admin access granted for path: {}", path);
            return chain.filter(exchange);
        }

        // ================= DB-driven role + URI + METHOD authorizationss =================
        for (String role : roles) {

            List<RealmProductRoleUrl> allowedUrls =
                    gatewayRoleService.getUrls(realm, product, role);

            if (allowedUrls == null || allowedUrls.isEmpty()) {
                continue;
            }

            for (RealmProductRoleUrl config : allowedUrls) {

                String allowedUri = config.getUri();
                if (allowedUri == null || allowedUri.isEmpty()) {
                    continue;
                }

                boolean uriMatches = false;

                if ("/".equals(allowedUri)) {
                    uriMatches = "/".equals(path);
                } else if (path.startsWith(allowedUri)) {
                    if (path.length() == allowedUri.length() ||
                            path.charAt(allowedUri.length()) == '/') {
                        uriMatches = true;
                    }
                }

                if (!uriMatches) {
                    continue;
                }

                // 🔥 HTTP METHOD CHECK (NEW)
                HttpMethod requestMethod = exchange.getRequest().getMethod();
                String allowedMethod = config.getHttpMethod();

                boolean methodMatches =
                        requestMethod != null &&
                                allowedMethod != null &&
                                requestMethod.name().equalsIgnoreCase(allowedMethod);

                if (!methodMatches) {
                    log.warn("⛔ METHOD NOT ALLOWED → role={} uri={} allowed={} requested={}",
                            role, allowedUri, allowedMethod, requestMethod);
                    continue;
                }

                log.info("✅ ACCESS GRANTED → role={} uri={} method={}",
                        role, allowedUri, requestMethod);

                String targetBaseUrl = config.getUrl();
                if (targetBaseUrl == null || targetBaseUrl.isEmpty()) {
                    log.error("❌ Target URL is null or empty for role '{}' and URI '{}'", role, allowedUri);
                    continue;
                }

                if (targetBaseUrl.endsWith("/")) {
                    targetBaseUrl = targetBaseUrl.substring(0, targetBaseUrl.length() - 1);
                }

                String fullTargetUrl = targetBaseUrl + path;
                return redirectToTarget(exchange, fullTargetUrl);
            }
        }

        log.warn("⛔ ACCESS DENIED → No matching role/URI/method for path: {}", path);
        response.setStatusCode(HttpStatus.FORBIDDEN);
        return response.setComplete();
    }


    /**
     * Forward request to target URL (proxy/forward - used for identity service)
     * Uses WebClient to forward the request and return the response
     */
    private Mono<Void> forwardRequest(ServerWebExchange exchange, String token, String fullTargetUrl) {
        ServerHttpRequest request = exchange.getRequest();
        
        // Build target URI with query parameters
        String queryString = request.getURI().getQuery();
        URI targetUri = queryString != null && !queryString.isEmpty() 
                ? URI.create(fullTargetUrl + "?" + queryString)
                : URI.create(fullTargetUrl);
        
        log.debug("🔄 Forwarding request to: {}", targetUri);
        
        // Forward request using WebClient (proxy/forward, not redirect)
        return forwardRequestWithWebClient(exchange, token, targetUri);
    }
    
    /**
     * Redirect user to target URL (HTTP 302 redirect - used for user access)
     */
    private Mono<Void> redirectToTarget(ServerWebExchange exchange, String fullTargetUrl) {
        ServerHttpRequest request = exchange.getRequest();
        ServerHttpResponse response = exchange.getResponse();
        
        // Build target URI with query parameters
        String queryString = request.getURI().getQuery();
        URI targetUri = queryString != null && !queryString.isEmpty() 
                ? URI.create(fullTargetUrl + "?" + queryString)
                : URI.create(fullTargetUrl);
        
        log.debug("🔄 Redirecting to: {}", targetUri);
        
        // Set HTTP 302 Found (redirect) status
        response.setStatusCode(HttpStatus.FOUND);
        response.getHeaders().setLocation(targetUri);
        
        return response.setComplete();
    }
    
    /**
     * Fallback: Forward request using WebClient if gateway routing not available
     */
    private Mono<Void> forwardRequestWithWebClient(ServerWebExchange exchange, String token, URI targetUri) {
        ServerHttpRequest request = exchange.getRequest();
        ServerHttpResponse response = exchange.getResponse();
        WebClient webClient = webClientBuilder.build();
        
        // Check if request has a body
        boolean hasBody = request.getMethod() == HttpMethod.POST || 
                         request.getMethod() == HttpMethod.PUT || 
                         request.getMethod() == HttpMethod.PATCH ||
                         request.getMethod() == HttpMethod.DELETE;

        if (hasBody) {
            return DataBufferUtils.join(request.getBody())
                    .flatMap(dataBuffer -> {
                        byte[] bodyBytes = null;
                        if (dataBuffer.readableByteCount() > 0) {
                            bodyBytes = new byte[dataBuffer.readableByteCount()];
                            dataBuffer.read(bodyBytes);
                        }
                        DataBufferUtils.release(dataBuffer);
                        return executeWebClientRequest(webClient, request, response, token, targetUri, bodyBytes);
                    })
                    .onErrorResume(e -> {
                        log.error("❌ Error reading request body for {}", targetUri, e);
                        return executeWebClientRequest(webClient, request, response, token, targetUri, null);
                    });
        } else {
            return executeWebClientRequest(webClient, request, response, token, targetUri, null);
        }
    }
    
    /**
     * Execute WebClient request and forward response (fallback only)
     */
    private Mono<Void> executeWebClientRequest(WebClient webClient,
                                             ServerHttpRequest request,
                                             ServerHttpResponse response,
                                             String token,
                                             URI targetUri,
                                             byte[] bodyBytes) {
        try {
            WebClient.RequestBodySpec requestSpec = webClient.method(request.getMethod())
                    .uri(targetUri)
                    .headers(headers -> {
                        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + token);
                        request.getHeaders().forEach((key, values) -> {
                            if (!key.equalsIgnoreCase(HttpHeaders.HOST) &&
                                    !key.equalsIgnoreCase(HttpHeaders.CONTENT_LENGTH)) {
                                headers.put(key, values);
                            }
                        });
                    });

            WebClient.RequestHeadersSpec<?> requestSpecWithBody = (bodyBytes != null && bodyBytes.length > 0)
                    ? requestSpec.bodyValue(bodyBytes)
                    : requestSpec;

            return requestSpecWithBody
                    .exchangeToMono(clientResponse -> {
                        response.setStatusCode(clientResponse.statusCode());
                        clientResponse.headers().asHttpHeaders()
                                .forEach((key, values) -> {
                                    String lowerKey = key.toLowerCase();
                                    if (!lowerKey.equals("content-length") &&
                                        !lowerKey.equals("transfer-encoding") &&
                                        !lowerKey.equals("connection") &&
                                        !lowerKey.equals("host")) {
                                        response.getHeaders().put(key, values);
                                    }
                                });
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
