package codestates.oauth.controller;

import codestates.oauth.auth.PrincipalDetails;
import codestates.oauth.model.Member;
import codestates.oauth.repository.MemberRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;

@Controller
@Slf4j
public class IndexController {

    @Autowired
    private MemberRepository memberRepository;
    @Autowired
    private PasswordEncoder bCryptPasswordEncoder;

//    @CrossOrigin(origins = "http://localhost:8080")
    @GetMapping("/")
    public String index(@AuthenticationPrincipal PrincipalDetails principalDetails,
                        Model model, HttpServletRequest request) {
        try {
            System.out.println(request.getHeader("Authorization"));
            System.out.println(principalDetails.getUsername());
        } catch (Exception e) {
            e.getMessage();
        }

        try {
            if (principalDetails != null) {
                model.addAttribute("username", principalDetails.getUsername());
            }
        } catch (NullPointerException e) {}
        return "index";
    }

    @GetMapping("/user")
    public @ResponseBody String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        return "user";
    }

    @GetMapping("/admin")
    public @ResponseBody String admin() {
        return "admin";
    }

    @GetMapping("/manager")
    public @ResponseBody String manager() {
        return "manager";
    }

    @GetMapping("/login")
    public String login() {
        return "loginForm";
    }

    @GetMapping("/join")
    public String joinForm() {
        return "joinForm";
    }

    @PostMapping("/join")
    public String join(Member member) {
        member.setRole("ROLE_USER");
        String rawPassword = member.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);
        member.setPassword(encPassword);

        memberRepository.save(member);

        return "redirect:/login";
    }

    //===========================================================================


    @GetMapping("/loginTest")
    public @ResponseBody String loginTest(Authentication authentication) {
        System.out.println("=========/loginTest=========");
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("authentication : " + principalDetails.getMember());
        return "세션 정보 확인";
    }

    @GetMapping("/loginTest2")
    public @ResponseBody String loginTest2(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        System.out.println("==========/loginTest2===========");
        System.out.println("userDetails : " + principalDetails.getMember());
        return "세션 정보 확인2";
    }


    @GetMapping("/loginTest3")////
    public @ResponseBody String loginOAuthTest(Authentication authentication,
                                               @AuthenticationPrincipal OAuth2User oauth) { //로그인된 유저의 Principal을 가져올 수 있도록 해주는 애노테이션

        System.out.println("===========/loginOAuthTest===========");
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        System.out.println("authentication : " + oAuth2User.getAttributes());
        System.out.println("oauth2User : " + oauth.getAttributes());

        return "세션 정보 확인3";
    }
}