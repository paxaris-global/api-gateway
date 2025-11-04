package com.paxaris.gateway.config;

import com.paxaris.gateway.service.GatewayRoleService;
import dto.RealmProductRoleUrl;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@Slf4j
@RequiredArgsConstructor
public class DynamicGatewayConfig {

    private final GatewayRoleService gatewayRoleService;

    @Bean
    public RouteLocator dynamicRoutes(RouteLocatorBuilder builder) {
        RouteLocatorBuilder.Builder routes = builder.routes();

        gatewayRoleService.getMemory().forEach((realm, products) -> {
            products.forEach((product, roles) -> {
                roles.forEach((role, urls) -> {
                    if (urls == null) return;
                    for (RealmProductRoleUrl url : urls) {
                        if (url.getUri() == null || url.getUri().isEmpty()) continue;
                        String routeId = role + "-" + url.getId();
                        log.info("Registering dynamic route: {} -> {}{}", routeId, url.getUrl(), url.getUri());
                        routes.route(routeId,
                                r -> r.path(url.getUri() + "/**")  // make sure it matches sub-paths
                                        .filters(f -> f.stripPrefix(0)) // do not strip path
                                        .uri(url.getUrl())
                        );
                    }
                });
            });
        });

        return routes.build();
    }
}
