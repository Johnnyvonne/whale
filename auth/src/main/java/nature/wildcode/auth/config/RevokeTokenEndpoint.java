package nature.wildcode.auth.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpoint;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;

@FrameworkEndpoint
public class RevokeTokenEndpoint {

    @Resource(name = "tokenServices")
    ConsumerTokenServices tokenServices;

    @Autowired
    private TokenStore tokenStore;

    @RequestMapping(method = RequestMethod.DELETE, value = "/oauth/token")
    @ResponseBody
    public void revokeToken(HttpServletRequest request, @RequestParam("token") String token) {
//        String authorization = request.getHeader("Authorization");
//        if (authorization != null && authorization.contains("Bearer")) {
//            String tokenId = authorization.substring("Bearer".length() + 1);
//            tokenServices.revokeToken(tokenId);
//        }
        System.out.println("haha");
        String authorization = request.getHeader("Authorization");
//        String authorization = request.getpa("Authorization");
        System.out.println(authorization);
        System.out.println(token);
        if (token != null && token.contains("bearer")) {
            String tokenId = token.substring("bearer".length() + 1);
            System.out.println(tokenId);
            OAuth2AccessToken accessToken = tokenStore.readAccessToken(tokenId);
            tokenStore.removeAccessToken(accessToken);
        }
    }

}