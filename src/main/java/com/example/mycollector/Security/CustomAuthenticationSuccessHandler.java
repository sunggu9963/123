package com.example.mycollector.Security;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;


@Component
public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final SessionManager sessionManager;

    public CustomAuthenticationSuccessHandler(SessionManager sessionManager) {
        this.sessionManager = sessionManager;
        setDefaultTargetUrl("/");
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {

        CustomUserPrincipal principal = (CustomUserPrincipal) authentication.getPrincipal();
        HttpSession session = request.getSession(true);

        // 원본의 sessionMgr.addUserSession(session, info) 대응
        sessionManager.addUserSession(session, principal.getAccount());

        super.onAuthenticationSuccess(request, response, authentication);
    }
}
