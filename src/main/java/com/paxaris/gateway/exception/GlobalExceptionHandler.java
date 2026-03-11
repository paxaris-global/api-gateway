package com.paxaris.gateway.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ServerWebExchange;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

import static com.paxaris.gateway.filter.CorrelationIdFilter.CORRELATION_ID_HEADER;
import static com.paxaris.gateway.filter.CorrelationIdFilter.CORRELATION_ID_KEY;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(RoleDataFetchException.class)
    public ResponseEntity<Map<String, Object>> handleRoleDataFetchException(RoleDataFetchException ex,
                                                                             ServerWebExchange exchange) {
        String correlationId = resolveCorrelationId(exchange);
        log.error("RoleDataFetchException correlationId={} message={}", correlationId, ex.getMessage(), ex);
        return buildResponse(
                HttpStatus.SERVICE_UNAVAILABLE,
                "ROLE_FETCH_ERROR",
                ex.getMessage(),
                correlationId,
                exchange
        );
    }

    @ExceptionHandler(TokenValidationException.class)
    public ResponseEntity<Map<String, Object>> handleTokenValidationException(TokenValidationException ex,
                                                                               ServerWebExchange exchange) {
        String correlationId = resolveCorrelationId(exchange);
        log.error("TokenValidationException correlationId={} message={}", correlationId, ex.getMessage(), ex);
        return buildResponse(
                HttpStatus.UNAUTHORIZED,
                "INVALID_TOKEN",
                ex.getMessage(),
                correlationId,
                exchange
        );
    }

    @ExceptionHandler(AuthorizationException.class)
    public ResponseEntity<Map<String, Object>> handleAuthorizationException(AuthorizationException ex,
                                                                             ServerWebExchange exchange) {
        String correlationId = resolveCorrelationId(exchange);
        log.warn("AuthorizationException correlationId={} message={}", correlationId, ex.getMessage());
        return buildResponse(
                HttpStatus.FORBIDDEN,
                "ACCESS_DENIED",
                ex.getMessage(),
                correlationId,
                exchange
        );
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGenericException(Exception ex,
                                                                       ServerWebExchange exchange) {
        String correlationId = resolveCorrelationId(exchange);
        log.error("UnhandledException correlationId={} message={}", correlationId, ex.getMessage(), ex);
        return buildResponse(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "ERROR",
                "Unexpected server error",
                correlationId,
                exchange
        );
    }

    private ResponseEntity<Map<String, Object>> buildResponse(HttpStatus httpStatus,
                                                               String status,
                                                               String message,
                                                               String correlationId,
                                                               ServerWebExchange exchange) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("timestamp", LocalDateTime.now());
        payload.put("status", status);
        payload.put("message", message);
        payload.put("correlationId", correlationId);
        payload.put("path", exchange != null ? exchange.getRequest().getURI().getPath() : "N/A");
        return ResponseEntity.status(httpStatus).body(payload);
    }

    private String resolveCorrelationId(ServerWebExchange exchange) {
        if (exchange == null) {
            return "N/A";
        }

        String correlationId = exchange.getRequest().getHeaders().getFirst(CORRELATION_ID_HEADER);
        if (StringUtils.hasText(correlationId)) {
            return correlationId;
        }

        Object correlationAttr = exchange.getAttribute(CORRELATION_ID_KEY);
        if (correlationAttr != null && StringUtils.hasText(correlationAttr.toString())) {
            return correlationAttr.toString();
        }

        return "N/A";
    }
}
