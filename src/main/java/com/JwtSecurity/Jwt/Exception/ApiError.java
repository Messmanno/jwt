package com.JwtSecurity.Jwt.Exception;

import lombok.Data;

import java.time.LocalDateTime;


@Data
public class ApiError {

    private String message;
    private int code;
    private LocalDateTime timestamp;
}
