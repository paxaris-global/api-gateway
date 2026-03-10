package com.paxaris.gateway;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;

import com.paxaris.gateway.config.RoleLoader;

@SpringBootTest(properties = {
        "PROJECT_MANAGEMENT_BASE_URL=http://localhost:8088",
        "IDENTITY_SERVICE_URL=http://localhost:8087",
        "KEYCLOAK_BASE_URL=http://localhost:8080",
        "project.management.base-url=http://localhost:8088"
})
class GatewayApplicationTests {

    @MockBean
    private RoleLoader roleLoader;

    @Test
    void contextLoads() {
    }
}
