package org.example.hello.security;

import org.springframework.core.task.SimpleAsyncTaskExecutor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.TestingAuthenticationProvider;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;

import java.util.Collection;

public class HelloSecurity {

    public static void main(String[] args) {
        // 初始化上下文
        initContext();

        // 获取上下文
        getContext();

        // 清除上下文
        SecurityContextHolder.clearContext();
    }

    static void initContext() {
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        /*
         * 认证信息
         * 包含如下几点：
         * 1、principal，登录用户
         * 2、credentials，校验信息
         * 3、authorities、角色信息
         */
        Authentication authentication = new TestingAuthenticationToken("username", "password", "USER_ROLE");
        // 权限认证上下文存放认证信息
        context.setAuthentication(authentication);

        // 认证提供者，提供认证方法
        AuthenticationProvider authenticationProvider = new TestingAuthenticationProvider();
        // 认证管理者，可能有多个认证提供者去认证身份
        ProviderManager providerManager = new ProviderManager(authenticationProvider);
        // 认证身份
        providerManager.authenticate(authentication);

        // SecurityContextHolder存储权限认证上下文
        SecurityContextHolder.setContext(context);


    }

    static void getContext() {
        UserDetails user = User.builder().username("username").password("").authorities("USER").build();
        UserDetails admin = User.builder().username("ADMIN").password("").authorities("USER", "ADMIN").build();
        UserDetailsService userDetailsService = new InMemoryUserDetailsManager(user, admin);


        SecurityContext securityContext = SecurityContextHolder.getContext();
        Authentication authentication = securityContext.getAuthentication();
        String name = authentication.getName();
        System.out.println(name);
        Object principal = authentication.getPrincipal();
        System.out.println(principal);
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        System.out.println(authorities);

        UserDetails userDetails = userDetailsService.loadUserByUsername(name);
        String username = userDetails.getUsername();
        System.out.println(username);

    }


}
