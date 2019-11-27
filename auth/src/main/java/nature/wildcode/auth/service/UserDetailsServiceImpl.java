package nature.wildcode.auth.service;

import nature.wildcode.auth.po.UserInfo;
import org.springframework.context.annotation.Primary;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Primary
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if("admin".equalsIgnoreCase(username)){
            UserInfo userInfo = new UserInfo();
            userInfo.setUsername(username);
            userInfo.setPassword("2Eae87480363c92cA84206978E8554f8d94e32e96b611cB7eB77174C3aFed50c52c10087cDdd4fb2ae66971a3628d160631a8d8C9857934a1482b4B92A5dC4f16945eA2c285Aa9Bb86f58ccE6dB4dDd8Bcd6896a6E5f889E84Fb2933E8b85801");

            return userInfo;
        }
        return null;
    }
}
