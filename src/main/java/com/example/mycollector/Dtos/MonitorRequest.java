package com.example.mycollector.Dtos;

import lombok.Data;

import java.util.List;

@Data
public class MonitorRequest {

    private String hostname;
    private String ip;
    private Double cpuUsage;
    private Double memoryUsage;
    private List<DiskUsage> diskUsages;
    private List<ProcessStatus> processes;
    private Long timestamp;

    private List<DbMetric> dbMetrics;
}