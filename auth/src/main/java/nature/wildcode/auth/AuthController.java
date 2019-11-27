package nature.wildcode.auth;

import nature.wildcode.auth.po.UserInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
public class AuthController {

    @Autowired
    private TokenStore tokenStore;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserDetailsService userDetailsService;

    @GetMapping("/user")
    public UserDetails getUser(@RequestParam("username") String username) {
        return userDetailsService.loadUserByUsername(username);
    }

    /**
     * 删除token
     *
     * @param
     * @return
     */
    @GetMapping("/logout")
    public String logout(HttpServletRequest request) {
        String authorization = request.getHeader("Authorization");
        if (authorization != null && authorization.contains("bearer")) {
            String tokenId = authorization.substring("bearer".length() + 1);
            OAuth2AccessToken accessToken = tokenStore.readAccessToken(tokenId);
            tokenStore.removeAccessToken(accessToken);
        }

        return "";
    }

//    @PostMapping("/registry")
//    public void registry(User user) {
    //新增用户时，密码加密
//        userRepository.save(new User(user.getUsername(), passwordEncoder.encode(user.getPassword())));
//    }
}
