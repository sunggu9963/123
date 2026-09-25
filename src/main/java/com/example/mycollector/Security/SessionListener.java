package com.example.mycollector.Security;

import org.springframework.stereotype.Component;

import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;


@Component
public class SessionListener implements HttpSessionListener {

    private final SessionManager sessionManager;

    public SessionListener(SessionManager sessionManager) {
        this.sessionManager = sessionManager;
    }

    @Override
    public void sessionDestroyed(HttpSessionEvent se) {
        sessionManager.removeSession(se.getSession());
    }
}
