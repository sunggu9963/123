package com.example.mycollector.Dtos;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class ServerSummary {
    private long total;       // 전체 서버 수
    private long online;      // ONLINE 서버 수
    private long offline;     // OFFLINE 서버 수
    private double avgCpu;    // ONLINE 서버 평균 CPU
    private double avgMemory; // ONLINE 서버 평균 메모리
}
