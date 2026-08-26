package com.example.mycollector.Controller;

import com.example.mycollector.Dtos.ApiResponse;
import com.example.mycollector.Dtos.MonitorRequest;
import com.example.mycollector.Dtos.ServerStatus;
import com.example.mycollector.Dtos.ServerSummary;
import com.example.mycollector.Service.MonitorService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Slf4j
@RestController
@RequiredArgsConstructor
public class apiController {

    private final MonitorService monitorService;

    /**
     * 에이전트 → 서버 상태 수집
     * POST /collect.do
     */
    @PostMapping("/collect.do")
    public ResponseEntity<ApiResponse> collect(@RequestBody MonitorRequest request) {
        try {
            if (request.getHostname() == null || request.getHostname().trim().isEmpty()) {
                return ResponseEntity.badRequest()
                        .body(new ApiResponse(400, "FAIL", "hostname은 필수입니다."));
            }
            monitorService.collect(request);
            return ResponseEntity.ok(ApiResponse.ok(request.getHostname() + " 수집 완료"));

        } catch (Exception e) {
            log.error("[collect] 오류: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError()
                    .body(ApiResponse.fail("수집 중 오류 발생: " + e.getMessage()));
        }
    }

    /**
     * 전체 서버 목록 조회 (ONLINE/OFFLINE 상태 포함)
     * GET /servers
     */
    @GetMapping("/servers")
    public ResponseEntity<List<ServerStatus>> getServers() {
        return ResponseEntity.ok(monitorService.getAllServersWithStatus());
    }

    /**
     * 특정 서버 상세 조회 (상태 포함)
     * GET /servers/{hostname}
     */
    @GetMapping("/servers/{hostname}")
    public ResponseEntity<?> getServer(@PathVariable String hostname) {
        ServerStatus server = monitorService.getServerWithStatus(hostname);
        if (server == null) {
            return ResponseEntity.ok(
                    new ApiResponse(404, "OFFLINE",
                            hostname + " 서버가 OFFLINE 또는 미등록 상태입니다."));
        }
        return ResponseEntity.ok(server);
    }

    /**
     * 요약 통계 조회 (전체/ONLINE/OFFLINE 수, 평균 CPU/메모리)
     * GET /servers/summary
     */
    @GetMapping("/servers/summary")
    public ResponseEntity<ServerSummary> getSummary() {
        return ResponseEntity.ok(monitorService.getSummary());
    }

    /**
     * 특정 서버 ONLINE 여부 확인
     * GET /servers/{hostname}/status
     */
    @GetMapping("/servers/{hostname}/status")
    public ResponseEntity<ApiResponse> getStatus(@PathVariable String hostname) {
        boolean online = monitorService.isOnline(hostname);
        String status = online ? "ONLINE" : "OFFLINE";
        return ResponseEntity.ok(
                new ApiResponse(200, status, hostname + " 는 현재 " + status + " 입니다."));
    }

    /**
     * 특정 서버 데이터 삭제
     * DELETE /servers/{hostname}
     */
    @DeleteMapping("/servers/{hostname}")
    public ResponseEntity<ApiResponse> deleteServer(@PathVariable String hostname) {
        try {
            monitorService.deleteServer(hostname);
            return ResponseEntity.ok(ApiResponse.ok(hostname + " 삭제 완료"));
        } catch (Exception e) {
            log.error("[delete] 오류: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError()
                    .body(ApiResponse.fail("삭제 중 오류 발생: " + e.getMessage()));
        }
    }
}