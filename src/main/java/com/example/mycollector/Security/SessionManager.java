package com.example.mycollector.Security;

import org.springframework.stereotype.Component;

import javax.servlet.http.HttpSession;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;


@Component
public class SessionManager {

    // sessionId -> HttpSession
    private final Map<String, HttpSession> sessionMap = new ConcurrentHashMap<>();
    // sessionId -> 로그인한 사용자 정보
    private final Map<String, UserAccount> userMap = new ConcurrentHashMap<>();


    public void addUserSession(HttpSession session, UserAccount user) {
        session.setAttribute("USER_SEQ", user.getUserSeq());
        session.setAttribute("USER_ID", user.getUserId());
        session.setAttribute("USER_NAME", user.getUserName());
        session.setAttribute("USER_ROLE", user.getUserRole());

        sessionMap.put(session.getId(), session);
        userMap.put(session.getId(), user);
    }


    public void removeSession(HttpSession session) {
        sessionMap.remove(session.getId());
        userMap.remove(session.getId());
    }

    public int getActiveSessionCount() {
        return sessionMap.size();
    }

    public UserAccount getUser(String sessionId) {
        return userMap.get(sessionId);
    }
}
