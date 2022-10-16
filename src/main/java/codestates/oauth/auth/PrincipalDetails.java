package codestates.oauth.auth;

import codestates.oauth.model.Member;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

@Data  //추가
//스프링 시큐리티 세션 정보는 단 1가지 타입인 Authentication 객체만 가지고 있을 수 있습니다.
//일반 로그인 → PrincipalDetails (implements UserDeatils)
//OAuth 로그인 → OAuth2User
//위와 같이 진행될 시 로그인 User 처리가 불편하게 된다. => 그래서 OAuth 유저도 PrincipalDetails로 묶으면 된다.
public class PrincipalDetails implements UserDetails, OAuth2User {  //추가

    private Member member;
    private Map<String, Object> attributes;  //추가

    //일반 로그인
    public PrincipalDetails(Member member) {
        this.member = member;
    }

    //OAuth 로그인
    public PrincipalDetails(Member member, Map<String, Object> attributes) {
        this.member = member;
        this.attributes = attributes;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collection = new ArrayList<>();
        collection.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return member.getRole();
            }
        });
        return new ArrayList<>(collection);
    }

    @Override
    public String getPassword() {
        return member.getPassword();
    }

    @Override
    public String getUsername() {
        return member.getUsername();
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

    @Override
    public String getName() {
        return null;
    }
}