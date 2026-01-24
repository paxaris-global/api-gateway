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
        ServerHttpResponse response = exchange.getResponse();
        String path = request.getURI().getPath();

        log.info("➡️ [GATEWAY] {} {}", request.getMethod(), path);

        // Skip auth endpoints
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
                .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                .flatMap(result -> authorize(result, exchange, chain))
                .onErrorResume(e -> {
                    log.error("❌ Validation error", e);
                    response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
                    return response.setComplete();
                });
    }

    private Mono<Void> authorize(Map<String, Object> result,
                                 ServerWebExchange exchange,
                                 GatewayFilterChain chain) {

        if (!"VALID".equals(result.get("status"))) {
            exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
            return exchange.getResponse().setComplete();
        }

        String realm = result.get("realm").toString();
        String product = result.get("product").toString();
        List<String> roles = (List<String>) result.get("roles");
        String azp = result.get("azp").toString();
        String path = exchange.getRequest().getURI().getPath();

        log.info("✅ Token OK | realm={} product={} roles={}", realm, product, roles);

        // Admin CLI → allow everything
        if ("admin-cli".equals(azp)) {
            return chain.filter(exchange);
        }

        // Block Keycloak admin paths
        if (path.startsWith("/identity/") && path.contains("/admin/")) {
            exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
            return exchange.getResponse().setComplete();
        }

        // Role → URL mapping check
        for (String role : roles) {
            List<RealmProductRoleUrl> allowedUrls =
                    gatewayRoleService.getUrls(realm, product, role);

            if (allowedUrls == null) continue;

            for (RealmProductRoleUrl url : allowedUrls) {
                if (path.equals(url.getUri())) {
                    log.info("✅ ACCESS GRANTED → {}", path);
                    return chain.filter(exchange);
                }
            }
        }

        log.warn("⛔ ACCESS DENIED → {}", path);
        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
        return exchange.getResponse().setComplete();
    }

    @Override
    public int getOrder() {
        return -1; // run first
    }
}
