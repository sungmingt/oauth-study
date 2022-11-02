package codestates.oauth.config.oauth;

import codestates.oauth.auth.PrincipalDetails;
import codestates.oauth.model.Member;
import codestates.oauth.repository.MemberRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service  //로그인 이후에 필요한 작업을 수행한다.
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private MemberRepository memberRepository;

    @Override  //구글로부터 받은 userRequest 데이터에 대한 후처리 로직
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        //서비스 제공업체를 반환 (google, naver 등)
        //String registrationId = userRequest.getClientRegistration().getRegistrationId();
        String provider = userRequest.getClientRegistration().getClientId();
        String providerId = oAuth2User.getAttribute("sub");
        String username = oAuth2User.getAttribute("name");
        String email = oAuth2User.getAttribute("email");
        String role = "ROLE_USER";

        Member memberEntity = memberRepository.findByUsername(username);

        if (memberEntity == null) {

            //OAuth로 처음 로그인한 경우 => 회원가입 처리
            //null이 아닌 경우에는 DB에 이미 존재하는 회원이기 때문에 별도 처리를 하지 않음.
            memberEntity = Member.builder()
                    .username(username)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            memberRepository.save(memberEntity);
        }

        return new PrincipalDetails(memberEntity, oAuth2User.getAttributes());
    }
}
