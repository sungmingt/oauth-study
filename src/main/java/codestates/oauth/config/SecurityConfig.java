package codestates.oauth.config;

import codestates.oauth.config.oauth.PrincipalOauth2UserService;
import codestates.oauth.filter.JwtAuthorizationFilter;
import codestates.oauth.filter.OAuthAuthenticationSuccessHandler;
import codestates.oauth.repository.MemberRepository;
import codestates.oauth.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

//@CrossOrigin(origins = "http://localhost:8080", allowedHeaders = "Authorization")
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final PrincipalOauth2UserService principalOauth2UserService; //추가
    private final JwtUtil jwtUtil;
    private final MemberRepository memberRepository;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.httpBasic().disable();
        http.headers().frameOptions().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.apply(new CustomDsl());

        http.authorizeRequests()
                .antMatchers("/user/**").authenticated()
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll()

                .and()
                .formLogin()
                .loginPage("/login")

                .and()
                .oauth2Login()
                .loginPage("/login")
                .successHandler(new OAuthAuthenticationSuccessHandler(new JwtUtil()))  //OAuth 로그인 성공 시 수행할 로직
                .userInfoEndpoint() // OAuth 로그인 성공 이후 사용자 정보를 가져올 때의 설정들을 담당
                .userService(principalOauth2UserService);  // OAuth 로그인 성공 시 후속 조치를 진행할 UserService 인터페이스의 구현체를 등록

        return http.build();
    }

    private class CustomDsl extends AbstractHttpConfigurer<CustomDsl, HttpSecurity> {
        @Override
        public void configure(HttpSecurity builder) throws Exception {
            AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);
            builder
                    .addFilter(new JwtAuthorizationFilter(authenticationManager, jwtUtil, memberRepository));
        }
    }
}