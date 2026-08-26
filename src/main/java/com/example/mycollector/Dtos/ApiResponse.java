package com.example.mycollector.Dtos;

import lombok.Data;

@Data
public class ApiResponse {
    private int status;
    private String result;
    private String message;

    public ApiResponse(int status, String result, String message) {
        this.status = status;
        this.result = result;
        this.message = message;
    }

    public static ApiResponse ok(String message) {
        return new ApiResponse(200, "SUCCESS", message);
    }

    public static ApiResponse fail(String message) {
        return new ApiResponse(500, "FAIL", message);
    }
}