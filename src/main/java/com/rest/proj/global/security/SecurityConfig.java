package com.rest.proj.global.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

// Spring Security 설정을 위한 클래스
@Configuration
// 웹 보안 활성화
@EnableWebSecurity
// final 필드에 대한 생성자를 자동으로 생성해주는 Lombok 어노테이션
@RequiredArgsConstructor
public class SecurityConfig {
    
    // SecurityFilterChain Bean을 생성하여 HTTP 보안 설정을 구성
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // HTTP 요청에 대한 인가 설정
                .authorizeHttpRequests((authorizeHttpRequests) -> authorizeHttpRequests
                        // 모든 요청("/**")에 대해 접근을 허용
                        .requestMatchers(new AntPathRequestMatcher("/**")).permitAll())
                // CSRF(Cross-Site Request Forgery) 보호 설정
                .csrf(
                        csrf -> csrf
                                // "/h2-console/**" 경로에 대한 CSRF 보호를 비활성화 (H2 콘솔 사용을 위함)
                                .ignoringRequestMatchers("/h2-console/**")
                )
                // HTTP 응답 헤더 설정
                .headers(
                        headers -> headers
                                // X-Frame-Options 헤더를 추가하여 클릭재킹 공격 방지
                                .addHeaderWriter(
                                        new XFrameOptionsHeaderWriter(
                                                // 동일한 출처(origin)의 프레임만 허용
                                                XFrameOptionsHeaderWriter.XFrameOptionsMode.SAMEORIGIN
                                        )
                                )
                );
        ;
        // 설정된 HttpSecurity 객체를 빌드하여 반환
        return http.build();
    }
}