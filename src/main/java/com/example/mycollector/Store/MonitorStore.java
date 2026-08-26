package com.example.mycollector.Store;

import com.example.mycollector.Dtos.MonitorRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@Slf4j
@Component
@RequiredArgsConstructor
public class MonitorStore {

    private final RedisTemplate<String, MonitorRequest> redisTemplate;

    private static final String KEY_PREFIX = "monitor:";

    /** 60초 동안 수신 없으면 OFFLINE 판정 (더 이상 Redis TTL이 아니라 timestamp 비교로 계산) */
    private static final long ONLINE_THRESHOLD_SECONDS = 60;

    /**
     * 서버 상태 저장 / 갱신 — TTL 없이 영구 저장 (레코드는 절대 자동 삭제되지 않음)
     */
    public void save(MonitorRequest request) {
        if (request.getHostname() == null || request.getHostname().trim().isEmpty()) {
            throw new IllegalArgumentException("hostname은 필수입니다.");
        }
        String key = KEY_PREFIX + request.getHostname();
        redisTemplate.opsForValue().set(key, request); // TTL 없음 -> 키는 delete() 전까지 유지
        log.info("[Redis] 저장: {} ({})", request.getHostname(), request.getIp());
    }

    /**
     * 특정 서버 조회 (null = 한 번도 수신된 적 없음)
     */
    public MonitorRequest findByHostname(String hostname) {
        return redisTemplate.opsForValue().get(KEY_PREFIX + hostname);
    }

    /**
     * 전체 서버 목록 조회 — ONLINE/OFFLINE 상관없이 등록된 모든 서버를 반환
     */
    public List<MonitorRequest> findAll() {
        Set<String> keys = redisTemplate.keys(KEY_PREFIX + "*");
        List<MonitorRequest> result = new ArrayList<>();
        if (keys == null || keys.isEmpty()) return result;

        for (String key : keys) {
            MonitorRequest req = redisTemplate.opsForValue().get(key);
            if (req != null) result.add(req);
        }
        result.sort((a, b) -> a.getHostname().compareToIgnoreCase(b.getHostname()));
        return result;
    }

    /**
     * 특정 서버 삭제 (명시적 삭제만 레코드를 제거함)
     */
    public void delete(String hostname) {
        redisTemplate.delete(KEY_PREFIX + hostname);
        log.info("[Redis] 삭제: {}", hostname);
    }

    /**
     * ONLINE 여부 — timestamp 기준으로 계산 (키 존재 여부가 아님)
     */
    public boolean isOnline(String hostname) {
        return getRemainingTtl(hostname) > 0;
    }

    /**
     * 남은 "온라인 유효시간" 조회 (초). 기존 메서드명/시맨틱 유지:
     * 양수면 ONLINE, -1이면 OFFLINE (레코드는 있지만 threshold 초과)
     * 레코드 자체가 없으면 -1
     */
    public long getRemainingTtl(String hostname) {
        MonitorRequest req = findByHostname(hostname);
        if (req == null || req.getTimestamp() == null) return -1;

        long elapsedSeconds = (System.currentTimeMillis() - req.getTimestamp()) / 1000;
        long remaining = ONLINE_THRESHOLD_SECONDS - elapsedSeconds;
        return remaining > 0 ? remaining : -1;
    }

    /**
     * 전체 서버 수 조회
     */
    public long countAll() {
        Set<String> keys = redisTemplate.keys(KEY_PREFIX + "*");
        return keys == null ? 0 : keys.size();
    }
}