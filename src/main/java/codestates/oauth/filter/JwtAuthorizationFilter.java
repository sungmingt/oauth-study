package codestates.oauth.filter;

import codestates.oauth.auth.PrincipalDetails;
import codestates.oauth.model.Member;
import codestates.oauth.repository.MemberRepository;
import codestates.oauth.util.JwtUtil;
import org.springframework.security.access.AuthorizationServiceException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private JwtUtil jwtUtil;
    private MemberRepository memberRepository;


    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, JwtUtil jwtUtil, MemberRepository memberRepository) {
        super(authenticationManager);
        this.jwtUtil = jwtUtil;
        this.memberRepository = memberRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("권한이 필요한 url 요청");

        String jwtHeader = request.getHeader("Authorization");

        if (jwtHeader == null || !jwtHeader.startsWith("Bearer ")) {
            chain.doFilter(request, response);
            return;
        }

        String token = jwtHeader.replace("Bearer ", "");
        String username = jwtUtil.validateToken(token);

        System.out.println(username);


        if (username != null) {
            Member memberEntity = memberRepository.findByUsername(username);

            PrincipalDetails principalDetails = new PrincipalDetails(memberEntity);
            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());

            SecurityContextHolder.getContext().setAuthentication(authentication);
            chain.doFilter(request, response);
        }

        super.doFilterInternal(request, response, chain);
    }
}
