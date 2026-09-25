package com.example.mycollector.Security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;


@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CustomAuthenticationSuccessHandler successHandler;

    public SecurityConfig(CustomAuthenticationSuccessHandler successHandler) {
        this.successHandler = successHandler;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // 로그인 페이지가 정적 HTML(login.html)이라 CSRF 토큰을 폼에 심기 어려워 비활성화.
            // (내부 관제용 단일 관리자 로그인이라는 전제하의 트레이드오프 - 필요하면
            //  CookieCsrfTokenRepository + JS로 토큰을 읽어 폼에 넣는 방식으로 나중에 켤 수 있음)
            .csrf().disable()

            .authorizeHttpRequests(authorize -> authorize
                    // /collect.do: 모니터링 에이전트가 데이터 올리는 API - 로그인 불가하니 허용
                    .antMatchers("/login", "/collect.do", "/favicon.ico").permitAll()
                    .anyRequest().authenticated()
            )

            .formLogin(form -> form
                    .loginPage("/login")                 // GET - 로그인 폼 페이지
                    .loginProcessingUrl("/login")         // POST - 로그인 처리 (Spring Security가 자동 처리)
                    .usernameParameter("username")
                    .passwordParameter("password")
                    .successHandler(successHandler)       // 성공 시 SessionManager 등록
                    .failureUrl("/login?error")
                    .permitAll()
            )

            .logout(logout -> logout
                    .logoutUrl("/logout")                 // GET/POST 둘 다 기본 지원
                    .logoutSuccessUrl("/login")
                    .invalidateHttpSession(true)          // → SessionListener가 감지해서 뒷정리
                    .permitAll()
            )

            // 대시보드 화면이 5초마다 부르는 API(/servers/**)는, 로그인 안 됐을 때
            // 로그인 페이지로 리다이렉트하지 않고 401만 내려줌 (JSON을 기대하는 fetch가 깨지지 않도록)
            .exceptionHandling(ex -> ex
                    .defaultAuthenticationEntryPointFor(
                            (request, response, authException) ->
                                    response.sendError(401, "로그인이 필요합니다."),
                            new AntPathRequestMatcher("/servers/**")
                    )
            );

        return http.build();
    }

    /** Spring Security 내장 BCryptPasswordEncoder - DaoAuthenticationProvider가 자동으로 사용 */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
}
