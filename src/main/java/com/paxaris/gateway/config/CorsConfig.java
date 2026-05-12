package com.paxaris.gateway.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.List;

import static org.springframework.web.cors.CorsConfiguration.ALL;

@Configuration
public class CorsConfig {

    /**
     * When true, any origin, method, and header are allowed on all paths ({@code /**}).
     * Disable in production if you need a strict allow-list ({@code GATEWAY_CORS_ALLOW_ALL=false}).
     */
    @Value("${gateway.cors.allow-all:true}")
    private boolean allowAll;

    /** When set, takes precedence over {@link #allowedOriginPatterns}. */
    @Value("${gateway.cors.allowed-origins:}")
    private String allowedOrigins;

    /** Used when {@link #allowedOrigins} is empty — supports any localhost port (e.g. ng serve SSR on 58851). */
    @Value("${gateway.cors.allowed-origin-patterns:http://localhost:*,http://127.0.0.1:*,https://*.ngrok-free.dev}")
    private String allowedOriginPatterns;

    @Value("${gateway.cors.allowed-methods}")
    private String allowedMethods;

    @Value("${gateway.cors.allowed-headers}")
    private String allowedHeaders;

    @Value("${gateway.cors.allow-credentials}")
    private boolean allowCredentials;

    @Bean
    public CorsWebFilter corsWebFilter() {
        CorsConfiguration config = new CorsConfiguration();
        if (allowAll) {
            config.setAllowedOriginPatterns(List.of(ALL));
            config.setAllowedMethods(List.of(ALL));
            config.setAllowedHeaders(List.of(ALL));
            config.setExposedHeaders(List.of(ALL));
            config.setMaxAge(3600L);
        } else if (StringUtils.hasText(allowedOrigins)) {
            config.setAllowedOrigins(parseCsv(allowedOrigins));
            config.setAllowedMethods(parseCsv(allowedMethods));
            config.setAllowedHeaders(parseCsv(allowedHeaders));
        } else {
            config.setAllowedOriginPatterns(parseCsv(allowedOriginPatterns));
            config.setAllowedMethods(parseCsv(allowedMethods));
            config.setAllowedHeaders(parseCsv(allowedHeaders));
        }
        config.setAllowCredentials(allowCredentials);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return new CorsWebFilter(source);
    }

    private List<String> parseCsv(String rawValue) {
        if (!StringUtils.hasText(rawValue)) {
            return List.of();
        }
        return Arrays.stream(rawValue.split(","))
                .map(String::trim)
                .filter(StringUtils::hasText)
                .toList();
    }
}
