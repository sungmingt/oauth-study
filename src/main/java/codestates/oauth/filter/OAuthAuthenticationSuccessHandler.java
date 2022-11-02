package codestates.oauth.filter;

import codestates.oauth.auth.PrincipalDetails;
import codestates.oauth.util.JwtUtil;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

//OAuth 로그인 성공 시 JWT 발급을 위한 successHandler
@Component
public class OAuthAuthenticationSuccessHandler implements AuthenticationSuccessHandler{

    private final JwtUtil jwtUtil;

    public OAuthAuthenticationSuccessHandler(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        System.out.println("=======OAuth Authentication Success Handler========");

        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        List<String> roles = principalDetails.getAuthorities().stream()
                .map(String::valueOf)
                .collect(Collectors.toList());

        String accessToken = jwtUtil.createAccessToken(principalDetails.getUsername(), roles);
        String refreshToken = jwtUtil.createRefreshToken(principalDetails.getUsername(), roles);

        response.addHeader("Authorization", "Bearer " + accessToken);
        response.addHeader("Refresh_token", "Bearer " + refreshToken);

        System.out.println("토큰 발급 완료");

        response.sendRedirect("/");
    }
}
