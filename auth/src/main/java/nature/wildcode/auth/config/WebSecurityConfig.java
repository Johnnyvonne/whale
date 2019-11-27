package nature.wildcode.auth.config;

import nature.wildcode.auth.service.UserDetailsServiceImpl;
import nature.wildcode.auth.util.EncryptUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;

import javax.servlet.*;
import java.io.IOException;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean(name = BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(detailsService()).passwordEncoder(passwordEncoder());
    }

    @Bean(name = BeanIds.USER_DETAILS_SERVICE)
    public UserDetailsService detailsService() {
        return new UserDetailsServiceImpl();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                // 匹配登录和获取token请求
                .antMatchers("/actuator")
                // 允许所有用户访问
                .permitAll()
                // 任何请求
                .anyRequest()
                // 必须是认证过的
                .authenticated()
                .and()
                // 禁用跨站点请求伪造，如果启用则需要新增一个请求参数
                .csrf()
                .disable()
                .addFilterAfter(new Filter() {
                    @Override
                    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
//                        System.out.println("haha");
//                        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
//
//                        if (principal instanceof UserDetails) {
//                            String username = ((UserDetails) principal).getUsername();
//                            System.out.println(username);
//                        } else {
//                            String username = principal.toString();
//                            System.out.println(username);
//                        }
                        filterChain.doFilter(servletRequest, servletResponse);
                    }
                }, WebAsyncManagerIntegrationFilter.class);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
//        NoOpPasswordEncoder
        return new PasswordEncoder() {
            @Override
            public String encode(CharSequence charSequence) {
                return EncryptUtil.mixedSaltedSHA512(charSequence.toString());
            }

            @Override
            public boolean matches(CharSequence charSequence, String s) {
                return EncryptUtil.matchMixedSaltedSHA512(charSequence.toString(), s);
            }
        };
    }

}
