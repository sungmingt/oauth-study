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

        ///////////여기서 헤더를 가져오지 못하는 듯 함.
        ////redirect 시 Authorization 헤더가 사라짐. CORS/redirect issue
        // Authorization 헤더를 받는 url은 google?state... 이다. 아마 다른 Origin이라 헤더값이 사라지는 듯 하다. redirect를 다른방식으로 이용...?
        //세션 사용 시 오류 해결. 하지만 jwt 사용 시 세션은 STATELESS 하는데...

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
