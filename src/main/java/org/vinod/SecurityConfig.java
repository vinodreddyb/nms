package org.vinod;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	DataSource dataSource;
	
	@Autowired
	public void configAuthentication(AuthenticationManagerBuilder auth) throws Exception {
		System.out.println("Data source------------------------>" + dataSource);
	  auth.jdbcAuthentication().dataSource(dataSource)
		.usersByUsernameQuery(
			"select username,password, enabled from tbl_users where username=?")
		.authoritiesByUsernameQuery(
			"select users.username, roles.role from tbl_user_roles as roles join tbl_users as users on users.userId = roles.userId where users.username= ?");
	}	
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {

	  http.authorizeRequests()
	  
		.antMatchers("/javax.faces.resource/*").anonymous()
		.antMatchers("/login.jsf").anonymous()
		.antMatchers("/**").access("hasRole('ROLE_ADMIN')")
		.and()
		  .formLogin().loginPage("/login.jsf").failureUrl("/faces/login.xhtml?error")
		  .usernameParameter("username").passwordParameter("password")
		.and()
		  .logout().logoutSuccessUrl("/faces/login.xhtml?logout")
		.and()
		  .exceptionHandling().accessDeniedPage("/403")
		.and()
		  .csrf();
	}
}
