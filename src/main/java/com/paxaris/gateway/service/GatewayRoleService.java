package com.paxaris.gateway.service;

import dto.RealmProductRole;
import dto.RealmProductRoleUrl;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Slf4j
@Service
@Getter
public class GatewayRoleService {

    private final Map<String, Map<String, Map<String, List<RealmProductRoleUrl>>>> memory = new ConcurrentHashMap<>();

    public void loadRoles(List<RealmProductRole> roles) {
        if (roles == null) return;
        for (RealmProductRole role : roles) {
            String realm = role.getRealmName();
            String product = role.getProductName() == null ? "" : role.getProductName();
            String roleName = role.getRoleName();
            List<RealmProductRoleUrl> urls = role.getUrls() == null ? List.of() : role.getUrls();

            memory
                    .computeIfAbsent(realm, r -> new ConcurrentHashMap<>())
                    .computeIfAbsent(product, p -> new ConcurrentHashMap<>())
                    .put(roleName, urls);

            log.debug("🔹 Loaded role '{}' for realm '{}' and product '{}' with URLs: {}", roleName, realm, product, urls);
        }
        log.info("✅ Roles loaded into memory");
    }

    public List<RealmProductRoleUrl> getUrls(String realm, String product, String role) {
        Map<String, Map<String, List<RealmProductRoleUrl>>> productMap = memory.getOrDefault(realm, Collections.emptyMap());
        if (product == null || product.isEmpty() || !productMap.containsKey(product)) {
            // fallback: search all products for this role
            for (Map<String, List<RealmProductRoleUrl>> rolesMap : productMap.values()) {
                if (rolesMap.containsKey(role)) return rolesMap.get(role);
            }
            return Collections.emptyList();
        }
        return productMap.getOrDefault(product, Collections.emptyMap()).getOrDefault(role, Collections.emptyList());
    }

    public List<RealmProductRoleUrl> getAllUrls(String realm, String product) {
        Map<String, Map<String, List<RealmProductRoleUrl>>> productMap = memory.getOrDefault(realm, Collections.emptyMap());
        List<RealmProductRoleUrl> allUrls = new ArrayList<>();
        if (product != null && !product.isEmpty() && productMap.containsKey(product)) {
            allUrls.addAll(productMap.get(product).values().stream()
                    .flatMap(List::stream)
                    .collect(Collectors.toList()));
        }
        productMap.values().forEach(roleMap ->
                allUrls.addAll(roleMap.values().stream().flatMap(List::stream).collect(Collectors.toList()))
        );
        return allUrls;
    }
}
