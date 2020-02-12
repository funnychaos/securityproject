package com.example.securityproject.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

/**
 * @Description:
 * @Author: solar
 * @Date: 2020-02-12 22:38
 * @Version: 1.00
 */
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	/*授权*/
	//链式编程
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		//首页所有人可以访问，功能页只有对应权限的人才可以访问
		http.authorizeRequests().antMatchers("/").permitAll()
				.antMatchers("/level1/**").hasRole("vip1")
				.antMatchers("/level2/**").hasRole("vip2")
				.antMatchers("/level3/**").hasRole("vip3");

		//没有权限自动跳转登陆页面
		http.formLogin();

		//注销
		http.logout();

		//防止网站工具：
		http.csrf().disable();

		//开启记住我功能
		http.rememberMe();
	}


	/*认证*/
	//密码需要加密
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		//现在从内存中虚拟数据，本应该从数据库中获取
		auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
				.withUser("solar").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1","vip2")
				.and()
				.withUser("admin").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1","vip2","vip3");
	}


}
