package com.paxaris.gateway.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.view.RedirectView;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class GatewayRedirectService {

    private static final Logger log = LoggerFactory.getLogger(GatewayRedirectService.class);
    private final Map<String, List<String>> tokenUrlMap = new ConcurrentHashMap<>();

    public void receiveTokenUrlsFromIdentityService(String accessToken, List<String> urls) {
        try {
            log.info("📨 [IDENTITY→GATEWAY] Receiving token + URLs from Identity Service...");
            if (accessToken != null && urls != null && !urls.isEmpty()) {
                tokenUrlMap.put(accessToken, urls);
                log.info("✅ Stored access token: {}", accessToken);
                log.info("🌐 Associated URLs: {}", urls);
            } else {
                log.warn("⚠️ Invalid token or empty URLs from Identity Service");
            }
        } catch (Exception e) {
            log.error("💥 [GATEWAY] Error saving token URLs: {}", e.getMessage(), e);
        }
    }

    public RedirectView redirectUser(String accessToken) {
        try {
            List<String> allowedUrls = tokenUrlMap.get(accessToken);
            RedirectView redirectView = new RedirectView();
            if (allowedUrls != null && !allowedUrls.isEmpty()) {
                String targetUrl = allowedUrls.get(0);
                log.info("➡️ Redirecting user to {}", targetUrl);
                redirectView.setUrl(targetUrl);
            } else {
                log.warn("⛔ No URLs found for token {}", accessToken);
                redirectView.setUrl("/error/no-access");
            }
            return redirectView;
        } catch (Exception e) {
            log.error("💥 [GATEWAY] Redirect error: {}", e.getMessage(), e);
            RedirectView redirectView = new RedirectView();
            redirectView.setUrl("/error");
            return redirectView;
        }
    }

    public List<String> getUrlsForToken(String accessToken) {
        try {
            return tokenUrlMap.get(accessToken);
        } catch (Exception e) {
            log.error("💥 [GATEWAY] Failed to retrieve URLs for token {}", accessToken, e);
            return List.of();
        }
    }
}
