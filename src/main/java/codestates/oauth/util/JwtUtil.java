package codestates.oauth.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.List;

@Component
public class JwtUtil {  //JWT 토큰의 생성, 검증 등의 작업을 담당한다.

    private final String secretKey = "asdfxcvsdfxcvsdf";
    private final Algorithm algorithm = Algorithm.HMAC512(secretKey);
    private final Date accessToken_Time = new Date(System.currentTimeMillis() + (60 * 1000 * 10));
    private final Date refreshToken_Time = new Date(System.currentTimeMillis() + (60 * 1000 * 30));

    //access Token 생성
    public String createAccessToken(String subject, List<String> roles) {
        String token = JWT.create()
                .withSubject(subject)
                .withClaim("roles", roles)
                .withExpiresAt(accessToken_Time)
                .sign(algorithm);
        System.out.println(token);

        return token;
    }

    //refresh Token 생성
    public String createRefreshToken(String subject, List<String> roles) {
        return JWT.create()
                .withSubject(subject)
                .withClaim("roles", roles)
                .withExpiresAt(refreshToken_Time)
                .sign(algorithm);
    }

    //Token 검증 + username 반환
    public String validateToken(String token) {
        return JWT.require(algorithm)
                .build()
                .verify(token)
                .getClaim("username")
                .asString();
    }
}
