package com.example.mycollector.Security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;


public class CustomUserPrincipal implements UserDetails {

    private final UserAccount account;

    public CustomUserPrincipal(UserAccount account) {
        this.account = account;
    }

    /** 로그인 성공 후처리(CustomAuthenticationSuccessHandler)에서 세션에 세팅할 때 사용 */
    public UserAccount getAccount() {
        return account;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        String role = account.getUserRole();
        return Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + (role != null ? role : "USER")));
    }

    @Override
    public String getPassword() {
        return account.getPasswordHash(); // DB에 저장된 BCrypt 해시
    }

    @Override
    public String getUsername() {
        return account.getUserId();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    // 동시 세션 제어(SecurityConfig의 maximumSessions)가 "같은 아이디로 로그인했는지"를
    // 판단할 때 이 equals()/hashCode()를 기준으로 비교한다. loadUserByUsername()이
    // 로그인마다 새 인스턴스를 만들기 때문에, 아이디 기준으로 비교하도록 반드시
    // 오버라이드해야 한다 (안 하면 매번 "다른 사용자"로 인식돼서 동시 세션 제어가 무력화됨).
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CustomUserPrincipal)) return false;
        CustomUserPrincipal other = (CustomUserPrincipal) o;
        return getUsername() != null && getUsername().equals(other.getUsername());
    }

    @Override
    public int hashCode() {
        return getUsername() != null ? getUsername().hashCode() : 0;
    }
}