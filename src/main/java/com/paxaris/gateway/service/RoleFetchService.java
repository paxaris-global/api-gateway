package com.paxaris.gateway.service;

import dto.RealmProductRole;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@Service
@Slf4j
@RequiredArgsConstructor
public class RoleFetchService {

    private final WebClient.Builder webClientBuilder;
    private final GatewayRoleService gatewayRoleService;

    private final ScheduledExecutorService scheduler =
            Executors.newSingleThreadScheduledExecutor();

    @Value("${project.management.base-url}")
    private String projectManagerBaseUrl;

    /**
     * Schedules role refresh 10 seconds after signup/create event
     */
    public void fetchRolesDelayed() {
        System.out.println(projectManagerBaseUrl);
        scheduler.schedule(() -> {
            try {
                log.info("⏳ [ROLE-REFRESH] Fetching roles from Project Manager after delay...");

                List<RealmProductRole> roles = webClientBuilder.build()
                        .get()
                        .uri(projectManagerBaseUrl + "/project/roles")
                        .retrieve()
                        .bodyToFlux(RealmProductRole.class)
                        .collectList()
                        .block(Duration.ofSeconds(10));

                if (roles != null && !roles.isEmpty()) {
                    gatewayRoleService.loadRoles(roles);
                    log.info("✅ [ROLE-REFRESH] Roles updated successfully.");
                } else {
                    log.warn("⚠️ [ROLE-REFRESH] No roles returned from Project Manager.");
                }

            } catch (Exception e) {
                log.error("💥 [ROLE-REFRESH] Failed to fetch roles", e);
            }

        }, 10, TimeUnit.SECONDS);
    }
}
