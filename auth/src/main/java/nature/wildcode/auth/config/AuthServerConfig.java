package nature.wildcode.auth.config;

import nature.wildcode.auth.po.UserInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Configuration
@EnableAuthorizationServer
public class AuthServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private AuthenticationManager authenticationManager;
//    @Autowired
//    private UserDetailsService userDetailsService;

    /**
     * 客户详细信息可以被初始化
     * @param clients
     * @throws Exception
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("clientapp")
                .secret("e2db080De819804e91bD7b2b8637014B8c0ee3f0Eb60abE524c85080e56f4078905E2780c62dEd16078e2429A776308b488cE490ee7545e81a4D89C82A5056aF7d6584c4F24B58Ae5Ebf645A24C341ef9bf10d1afF60F92720D4e3e26f3D28B4")
                // 密码模式
                .authorizedGrantTypes("password", "refresh_token")
                .accessTokenValiditySeconds(3600)       // 1 hour
                .refreshTokenValiditySeconds(86400)  // 1 day
                .scopes("read_userinfo", "read_contacts");
                //四种授权方式
//                .authorizedGrantTypes("implicit", "refresh_token", "password", "authorization_code");
    }
    @Autowired
    private UserDetailsService userDetailsService;
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
//        final TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
//        tokenEnhancerChain.setTokenEnhancers(Arrays.asList(jwtTokenConverter(), jwtTokenConverter()));
//        endpoints.tokenStore(jwtTokenStore()).tokenEnhancer(tokenEnhancerChain).authenticationManager(authenticationManager);
        endpoints
                .tokenStore(jwtTokenStore())
                .userDetailsService(userDetailsService)
//                .tokenServices(tokenServices())
                .tokenEnhancer(jwtTokenConverter())
                .reuseRefreshTokens(true)
                .authenticationManager(authenticationManager);
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.tokenKeyAccess("permitAll()").checkTokenAccess("isAuthenticated()");
    }

    @Primary
    @Bean
    public DefaultTokenServices tokenServices() {
        DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(jwtTokenStore());
//        defaultTokenServices.setTokenEnhancer(jwtTokenConverter());
        defaultTokenServices.setSupportRefreshToken(true);
        defaultTokenServices.setAccessTokenValiditySeconds((int) TimeUnit.MINUTES.toSeconds(30));
        defaultTokenServices.setRefreshTokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(1));
        return defaultTokenServices;
    }

    /**
     * 保存、删除、查询token
     * @return TokenStore
     */
    @Bean
    public TokenStore jwtTokenStore() {
        return new JwtTokenStore(jwtTokenConverter());
    }

    /**
     * TokenEnhancer实现类，扩展Token，AccessToken使用JWT，自定义JWT，对称加密，非对称加密
     * @return JwtAccessTokenConverter
     */
    @Bean
    protected JwtAccessTokenConverter jwtTokenConverter() {
        JwtAccessTokenConverter converter = new CustomTokenEnhancer();
        DefaultAccessTokenConverter defaultAccessTokenConverter = new DefaultAccessTokenConverter();
        defaultAccessTokenConverter.setUserTokenConverter(new CustomerAccessTokenConverter());
        converter.setAccessTokenConverter(defaultAccessTokenConverter);
        converter.setSigningKey("123456");
//        converter.setVerifierKey("123456");
        return converter;
    }

    class CustomerAccessTokenConverter extends DefaultUserAuthenticationConverter {

        @Override
        public Map<String, ?> convertUserAuthentication(Authentication authentication) {
            Map<String, Object> response = new LinkedHashMap();
            // 自定义JWT payload
            response.put("user_name", authentication.getName());
            response.put("email", ((UserInfo)authentication.getPrincipal()).getEmail());
            if (authentication.getAuthorities() != null && !authentication.getAuthorities().isEmpty()) {
                response.put("authorities", AuthorityUtils.authorityListToSet(authentication.getAuthorities()));
            }

            return response;
        }
    }

    class CustomTokenEnhancer extends JwtAccessTokenConverter {

        @Override
        public OAuth2AccessToken enhance(OAuth2AccessToken oAuth2AccessToken, OAuth2Authentication oAuth2Authentication) {
            OAuth2AccessToken accessToken = super.enhance(oAuth2AccessToken, oAuth2Authentication);
            final Map<String, Object> additionalInfo = new HashMap<>();
            UserInfo user = (UserInfo) oAuth2Authentication.getUserAuthentication().getPrincipal();
            additionalInfo.put("email", user.getEmail());
//            additionalInfo.put("authorities", user.getAuthorities());
            // 添加/oauth/token接口返回值额外字段
            // 在这里添加权限信息、用户信息提供给web端
            ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInfo);
            return accessToken;
        }
    }
}
