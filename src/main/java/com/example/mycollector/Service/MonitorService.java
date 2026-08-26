package com.example.mycollector.Service;

import com.example.mycollector.Dtos.MonitorRequest;
import com.example.mycollector.Dtos.ServerStatus;
import com.example.mycollector.Dtos.ServerSummary;
import com.example.mycollector.Store.MonitorStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class MonitorService {

    private final MonitorStore monitorStore;

    /** CPU 경고 임계값 (%) */
    private static final double CPU_WARN_THRESHOLD = 80.0;

    /** 메모리 경고 임계값 (%) */
    private static final double MEM_WARN_THRESHOLD = 85.0;

    /** 디스크 경고 임계값 (%) */
    private static final double DISK_WARN_THRESHOLD = 90.0;

    /**
     * 에이전트 수신 데이터 저장
     */
    public void collect(MonitorRequest request) {
        if (request.getTimestamp() == null) {
            request.setTimestamp(System.currentTimeMillis());
        }
        monitorStore.save(request);
        checkThresholds(request); // 임계값 초과 여부 로그 기록
    }

    /**
     * 전체 서버 목록 조회 (상태 포함)
     */
    public List<ServerStatus> getAllServersWithStatus() {
        return monitorStore.findAll().stream()
                .map(req -> {
                    long ttl = monitorStore.getRemainingTtl(req.getHostname());
                    String status = ttl > 0 ? "ONLINE" : "OFFLINE";
                    return ServerStatus.of(req, status, ttl);
                })
                .collect(Collectors.toList());
    }

    /**
     * 전체 서버 목록 조회 (기존 호환용)
     */
    public List<MonitorRequest> getAllServers() {
        return monitorStore.findAll();
    }

    /**
     * 특정 서버 조회 - 상태 포함
     */
    public ServerStatus getServerWithStatus(String hostname) {
        MonitorRequest req = monitorStore.findByHostname(hostname);
        if (req == null) return null;
        long ttl = monitorStore.getRemainingTtl(hostname);
        String status = ttl > 0 ? "ONLINE" : "OFFLINE";
        return ServerStatus.of(req, status, ttl);
    }

    /**
     * 특정 서버 조회 (기존 호환용)
     */
    public MonitorRequest getServer(String hostname) {
        return monitorStore.findByHostname(hostname);
    }

    /**
     * ONLINE 여부
     */
    public boolean isOnline(String hostname) {
        return monitorStore.isOnline(hostname);
    }

    /**
     * 요약 통계 조회
     */
    public ServerSummary getSummary() {
        List<MonitorRequest> all = monitorStore.findAll();
        long total = all.size();

        List<MonitorRequest> onlineList = all.stream()
                .filter(req -> monitorStore.isOnline(req.getHostname()))
                .collect(Collectors.toList());

        long online = onlineList.size();
        long offline = total - online;

        double avgCpu = onlineList.stream()
                .filter(req -> req.getCpuUsage() != null)
                .mapToDouble(MonitorRequest::getCpuUsage)
                .average()
                .orElse(0.0);

        double avgMemory = onlineList.stream()
                .filter(req -> req.getMemoryUsage() != null)
                .mapToDouble(MonitorRequest::getMemoryUsage)
                .average()
                .orElse(0.0);

        // 소수점 1자리 반올림
        avgCpu    = Math.round(avgCpu    * 10.0) / 10.0;
        avgMemory = Math.round(avgMemory * 10.0) / 10.0;

        return new ServerSummary(total, online, offline, avgCpu, avgMemory);
    }

    /**
     * 특정 서버 삭제
     */
    public void deleteServer(String hostname) {
        monitorStore.delete(hostname);
    }

    /**
     * 임계값 초과 시 로그 경고
     */
    private void checkThresholds(MonitorRequest req) {
        String host = req.getHostname();

        if (req.getCpuUsage() != null && req.getCpuUsage() >= CPU_WARN_THRESHOLD) {
            log.warn("[경고] {} CPU 사용률 높음: {}%", host, req.getCpuUsage());
        }

        if (req.getMemoryUsage() != null && req.getMemoryUsage() >= MEM_WARN_THRESHOLD) {
            log.warn("[경고] {} 메모리 사용률 높음: {}%", host, req.getMemoryUsage());
        }

        if (req.getDiskUsages() != null) {
            req.getDiskUsages().stream()
                    .filter(d -> d.getUsage() != null && d.getUsage() >= DISK_WARN_THRESHOLD)
                    .forEach(d -> log.warn("[경고] {} 디스크 사용률 높음: {} {}%",
                            host, d.getMountPoint(), d.getUsage()));
        }

        if (req.getProcesses() != null) {
            req.getProcesses().stream()
                    .filter(p -> Boolean.FALSE.equals(p.getRunning()))
                    .forEach(p -> log.warn("[경고] {} 프로세스 중지됨: {}", host, p.getName()));
        }
    }
}