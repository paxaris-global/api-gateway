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
            Executors.newSingleThreadScheduledExecutor(); /* (updated line for reload) */

    @Value("${PROJECT_MANAGEMENT_BASE_URL}")
    private String projectManagerBaseUrl;

    public void fetchRolesDelayed() {
        scheduler.schedule(() -> {  /* (updated line for reload) */
            try {
                log.info("⏳ Fetching roles from Project Manager after 10s delay..."); /* (updated line for reload) */

                List<RealmProductRole> roles = webClientBuilder.build()
                        .get()
                        .uri(projectManagerBaseUrl + "/project/roles")
                        .retrieve()
                        .bodyToFlux(RealmProductRole.class)
                        .collectList()
                        .block(Duration.ofSeconds(10));

                if (roles != null && !roles.isEmpty()) {
                    gatewayRoleService.loadRoles(roles);  /* (updated line for reload) */
                    log.info("✅ Roles updated successfully!"); /* (updated line for reload) */
                } else {
                    log.warn("⚠️ No roles returned from PM service"); /* (updated line for reload) */
                }

            } catch (Exception e) {
                log.error("💥 Failed to fetch roles", e); /* (updated line for reload) */
            }
        }, 10, TimeUnit.SECONDS);
    }
}
