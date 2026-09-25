package com.example.mycollector.Security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;

/**
 * Spring Security가 요구하는 UserDetails 구현체.
 * authentication.getPrincipal()을 캐스팅하면 이 객체가 나오고,
 * getAccount()로 DB에서 조회한 원본 정보(userSeq/userName/userRole 등)에 접근할 수 있다.
 */
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

    // IP/MAC/UUID/계정 잠금 등 세부 체크는 하지 않기로 했으므로 전부 true 고정
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
}
