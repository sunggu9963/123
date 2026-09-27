package com.example.mycollector.Security;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 세션이 얼마나 남았는지 확인하기 위한 진단용 엔드포인트.
 * 로그인된 상태에서만 접근 가능 (SecurityConfig의 anyRequest().authenticated()에 걸림 -
 * 별도로 permitAll 처리 안 함).
 *
 * 사용법: 로그인한 브라우저에서 GET /session-info 호출.
 *
 * 주의: 이 엔드포인트 자체를 호출하는 것도 "세션에 접근하는 요청"이라
 * 호출할 때마다 세션의 활동 시각이 갱신된다 (일반적인 요청과 동일).
 * 즉 이 엔드포인트를 계속 호출하면 타임아웃이 계속 늦춰지므로,
 * "진짜 타임아웃되는지" 확인하려면 한동안 아무 요청도 안 보내다가 호출해봐야 한다.
 */
@RestController
public class SessionInfoController {

    @GetMapping("/session-info")
    public Map<String, Object> sessionInfo(HttpSession session) {
        long now = System.currentTimeMillis();
        long lastAccessed = session.getLastAccessedTime();
        long created = session.getCreationTime();
        int maxInactiveSeconds = session.getMaxInactiveInterval();

        // getLastAccessedTime()은 "이번 요청 이전, 마지막으로 접근했던 시각"을 반환하므로
        // 이 값 기준으로 경과 시간을 계산하면 "이번 호출 직전까지 실제로 얼마나 비어있었는지"를 알 수 있음
        long elapsedSeconds = (now - lastAccessed) / 1000;
        long remainingSeconds = maxInactiveSeconds - elapsedSeconds;

        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

        Map<String, Object> info = new LinkedHashMap<>();
        info.put("sessionId", session.getId());
        info.put("createdAt", sdf.format(new Date(created)));
        info.put("lastAccessedAt", sdf.format(new Date(lastAccessed)));
        info.put("maxInactiveIntervalSeconds", maxInactiveSeconds);
        info.put("elapsedSecondsSinceLastAccess", elapsedSeconds);
        info.put("remainingSeconds", Math.max(remainingSeconds, 0));
        info.put("isNew", session.isNew());
        return info;
    }
}
