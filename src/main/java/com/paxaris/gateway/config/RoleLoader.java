package com.paxaris.gateway.config;

import com.paxaris.gateway.service.GatewayRoleService;
import dto.RealmProductRole;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.time.Duration;
import java.util.List;

@Component
@RequiredArgsConstructor
@Slf4j
public class RoleLoader implements ApplicationRunner {

    private final WebClient.Builder webClientBuilder;
    private final GatewayRoleService gatewayRoleService;

    @Value("${project.management.base-url}")
    private String projectManagerBaseUrl;

    @Value("${gateway.project-roles-path}")
    private String projectRolesPath;

    @Value("${gateway.role-loader.max-retries}")
    private int maxRetries;

    @Value("${gateway.role-loader.initial-retry-ms}")
    private long initialRetryMs;

    @Value("${gateway.role-loader.request-timeout-seconds}")
    private long requestTimeoutSeconds;

    @Value("${gateway.role-loader.default-realm}")
    private String defaultRealm;

    @Override
    public void run(ApplicationArguments args) throws InterruptedException {
        log.info("📥 [GATEWAY] Fetching roles from Project Manager on startup...");

        int attempt = 0;
        long retryInterval = initialRetryMs;
        boolean success = false;

        while (!success && attempt < maxRetries) {
            attempt++;
            try {
                List<RealmProductRole> roles = webClientBuilder.build()
                        .get()
                    .uri(projectManagerBaseUrl  + projectRolesPath)
                        .retrieve()
                        .bodyToFlux(RealmProductRole.class)
                        .collectList()
                        .block(Duration.ofSeconds(requestTimeoutSeconds));

                if (roles == null || roles.isEmpty()) {
                    gatewayRoleService.loadRoles(List.of());
                    log.warn("⚠️ [GATEWAY] Project Manager returned no roles; starting with empty role cache");
                    success = true;
                } else {
                    roles.forEach(role -> {
                        if (role.getRealmName() == null || role.getRealmName().isEmpty()) {
                            role.setRealmName(defaultRealm);
                        }
                        if (role.getProductName() == null) {
                            role.setProductName("");
                        }
                        log.info("🌐 [GATEWAY] Role: {} | Realm: {} | Product: {} | URLs: {}",
                                role.getRoleName(), role.getRealmName(), role.getProductName(), role.getUrls());
                    });

                    gatewayRoleService.loadRoles(roles);
                    log.info("✅ [GATEWAY] Roles successfully loaded into memory");
                    success = true;
                }

            } catch (WebClientResponseException e) {
                log.error("❌ [GATEWAY] Project Manager returned error {}: {}", e.getRawStatusCode(), e.getResponseBodyAsString());
            } catch (Exception e) {
                log.warn("💥 [GATEWAY] Attempt {} failed: {}", attempt, e.getMessage());
            }

            if (!success) {
                log.info("⏳ Retrying in {} ms...", retryInterval);
                Thread.sleep(retryInterval);
                retryInterval = initialRetryMs;
            }
        }

        if (!success) {
            log.error("❌ [GATEWAY] Failed to fetch roles from Project Manager after {} attempts", maxRetries);
        }
    }
}
