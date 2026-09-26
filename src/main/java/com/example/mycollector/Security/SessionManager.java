package com.example.mycollector.Security;

import org.springframework.stereotype.Component;

import javax.servlet.http.HttpSession;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 기존 hsck 프로젝트의 SessionManager를 단순화해서 포팅한 버전.
 *
 * 뺀 것: IP/MAC/UUID 체크, 중복 로그인 시 기존 세션 강제 종료(exclusiveLogin)
 * 남긴 것: "로그인 성공 시 세션에 사용자 정보를 세팅"하고,
 *          "현재 로그인 중인 세션을 서버 메모리에서 추적"하는 핵심 기능,
 *          "세션 타임아웃 값을 DB에서 조회해서 적용"하는 기능
 *
 * 세션 타임아웃: 원본처럼 tbl_system_env(tag=SESSIONVALUE)를 매 로그인마다 조회해서
 * 분 단위 값을 읽어온다 (SystemEnvDao 참고). 값이 없거나 파싱 실패하면 원본과 동일한
 * 기본값(10분)을 사용한다.
 *
 * Spring Security 적용 후 달라진 점: 로그인 여부 자체는 이제 Spring Security의
 * SecurityContext(세션에 자동 저장됨)로 판단하므로, 예전에 있던 "LOGIN_OK" 같은
 * 커스텀 플래그는 더 이상 두지 않는다. 여기서는 순수하게 "누가 로그인 중인지"를
 * 세션 값으로 세팅하고 추적하는 역할만 담당한다.
 */
@Component
public class SessionManager {

    private static final String TAG_SESSION_VALUE = "SESSIONVALUE";
    // 원본의 SESSION_TIME_DEFAULT = 10(분)과 동일
    private static final int SESSION_TIME_DEFAULT_MINUTES = 10;

    // sessionId -> HttpSession
    private final Map<String, HttpSession> sessionMap = new ConcurrentHashMap<>();
    // sessionId -> 로그인한 사용자 정보
    private final Map<String, UserAccount> userMap = new ConcurrentHashMap<>();

    private final SystemEnvDao systemEnvDao;

    public SessionManager(SystemEnvDao systemEnvDao) {
        this.systemEnvDao = systemEnvDao;
    }

    /**
     * 로그인 성공 시 호출 (CustomAuthenticationSuccessHandler에서 호출).
     * - DB에서 세션 타임아웃 값을 조회해서 적용
     * - 세션에 사용자 정보를 값으로 세팅
     * - 서버 메모리(sessionMap/userMap)에도 등록해서 "현재 로그인 중인 사용자" 추적 가능하게 함
     */
    public void addUserSession(HttpSession session, UserAccount user) {
        session.setMaxInactiveInterval(resolveSessionTimeoutSeconds());

        session.setAttribute("USER_SEQ", user.getUserSeq());
        session.setAttribute("USER_ID", user.getUserId());
        session.setAttribute("USER_NAME", user.getUserName());
        session.setAttribute("USER_ROLE", user.getUserRole());

        sessionMap.put(session.getId(), session);
        userMap.put(session.getId(), user);
    }

    private int resolveSessionTimeoutSeconds() {
        String tagValue = systemEnvDao.getTagValue(TAG_SESSION_VALUE);
        int minutes = SESSION_TIME_DEFAULT_MINUTES;

        if (tagValue != null && !tagValue.trim().isEmpty()) {
            try {
                minutes = Integer.parseInt(tagValue.trim());
            } catch (NumberFormatException e) {
                // 원본처럼 잘못된 값이면 기본값을 그대로 사용
            }
        }
        return minutes * 60;
    }

    /**
     * 세션이 끝날 때(로그아웃 또는 타임아웃) 호출.
     * SessionListener(HttpSessionListener)에서 세션 소멸 시 자동으로 호출됨.
     */
    public void removeSession(HttpSession session) {
        sessionMap.remove(session.getId());
        userMap.remove(session.getId());
    }

    /** 현재 로그인 중인 세션 개수 (필요하면 관제 화면 등에 활용 가능) */
    public int getActiveSessionCount() {
        return sessionMap.size();
    }

    /** 특정 세션ID로 로그인한 사용자 정보 조회 */
    public UserAccount getUser(String sessionId) {
        return userMap.get(sessionId);
    }
}
