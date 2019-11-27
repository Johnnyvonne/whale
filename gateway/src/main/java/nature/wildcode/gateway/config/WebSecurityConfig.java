package nature.wildcode.gateway.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;

import javax.servlet.*;
import java.io.IOException;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * 认证方法：获得Assess Token，查询redis，得到对应的JWT就算验证通过，细节由后续微服务继续验证
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .inMemoryAuthentication()
                .withUser("guest").password("guest").authorities("WRIGTH_READ")
                .and()
                .withUser("admin").password("admin").authorities("WRIGTH_READ", "WRIGTH_WRITE");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                // 匹配登录和获取token请求
                .antMatchers("/login","/oauth/**", "/auth/**")
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
        .addFilterBefore(new Filter() {
            @Override
            public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
                System.out.println("haha");
                filterChain.doFilter(servletRequest, servletResponse);
            }
        }, WebAsyncManagerIntegrationFilter.class);
    }


}
