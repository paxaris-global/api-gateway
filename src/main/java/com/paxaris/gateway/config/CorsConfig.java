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

@Configuration
public class CorsConfig {

    @Value("${gateway.cors.allowed-origins}")
    private String allowedOrigins;

    @Value("${gateway.cors.allowed-methods}")
    private String allowedMethods;

    @Value("${gateway.cors.allowed-headers}")
    private String allowedHeaders;

    @Value("${gateway.cors.allow-credentials}")
    private boolean allowCredentials;

    @Bean
    public CorsWebFilter corsWebFilter() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(parseCsv(allowedOrigins));
        config.setAllowedMethods(parseCsv(allowedMethods));
        config.setAllowedHeaders(parseCsv(allowedHeaders));
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
