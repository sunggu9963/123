package com.example.mycollector.Dtos;

import lombok.Data;

import java.util.List;

@Data
public class MonitorRequest {

    private String hostname;       // 서버 호스트명

    private String ip;             // 서버 IP

    private Double cpuUsage;       // CPU 사용률 (%)

    private Double memoryUsage;    // 메모리 사용률 (%)

    private List<DiskUsage> diskUsages;      // 디스크 파티션 목록

    private List<ProcessStatus> processes;   // 감시 프로세스 목록

    private Long timestamp;        // 수집 시각 (epoch ms)
}