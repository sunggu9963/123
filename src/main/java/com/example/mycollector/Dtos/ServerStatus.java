package com.example.mycollector.Dtos;

import lombok.Data;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.List;

@Data
public class ServerStatus {

    private String hostname;
    private String ip;
    private String status;          // "ONLINE" | "OFFLINE"
    private Double cpuUsage;
    private Double memoryUsage;
    private List<DiskUsage> diskUsages;
    private List<ProcessStatus> processes;
    private Long timestamp;         // 마지막 수신 epoch ms
    private long remainingTtl;      // 남은 TTL (초), -1이면 만료
    private List<DbMetric> dbMetrics;


    // 마지막 수신 시각을 포맷된 문자열로 반환
    public String getLastSeenFormatted() {
        if (timestamp == null) return "-";
        LocalDateTime dt = LocalDateTime.ofInstant(
                Instant.ofEpochMilli(timestamp),
                ZoneId.systemDefault()
        );
        return dt.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
    }

    // MonitorRequest + 상태 정보 조합
    public static ServerStatus of(MonitorRequest req, String status, long ttl) {
        ServerStatus s = new ServerStatus();
        s.setHostname(req.getHostname());
        s.setIp(req.getIp());
        s.setStatus(status);
        s.setCpuUsage(req.getCpuUsage());
        s.setMemoryUsage(req.getMemoryUsage());
        s.setDiskUsages(req.getDiskUsages());
        s.setProcesses(req.getProcesses());
        s.setTimestamp(req.getTimestamp());
        s.setRemainingTtl(ttl);
        s.setDbMetrics(req.getDbMetrics() != null ? req.getDbMetrics() : Collections.emptyList());
        return s;
    }
}
