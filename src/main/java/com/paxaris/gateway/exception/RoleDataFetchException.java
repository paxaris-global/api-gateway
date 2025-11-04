package com.paxaris.gateway.exception;

public class RoleDataFetchException extends RuntimeException {
    public RoleDataFetchException(String message) {
        super(message);
    }

    public RoleDataFetchException(String message, Throwable cause) {
        super(message, cause);
    }
}
