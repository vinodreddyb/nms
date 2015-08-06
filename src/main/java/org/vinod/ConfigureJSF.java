package org.vinod;

import javax.faces.webapp.FacesServlet;
import javax.servlet.ServletContext;

import org.springframework.boot.context.embedded.ServletListenerRegistrationBean;
import org.springframework.boot.context.embedded.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.context.ServletContextAware;

import com.sun.faces.config.ConfigureListener;

@Configuration
public class ConfigureJSF implements ServletContextAware{

	 @Override
	    public void setServletContext(ServletContext servletContext) {
	        servletContext.setInitParameter("com.sun.faces.forceLoadConfiguration", Boolean.TRUE.toString());       
	    }
	 @Bean
	    public ServletRegistrationBean servletRegistrationBean() {
	        FacesServlet servlet = new FacesServlet();
	        ServletRegistrationBean servletRegistrationBean = new ServletRegistrationBean(servlet, "*.jsf");
			return servletRegistrationBean;
	    }
	    @Bean
	    public ServletListenerRegistrationBean<ConfigureListener> jsfConfigureListener() {
	        return new ServletListenerRegistrationBean<ConfigureListener>(
	            new ConfigureListener());
	    }
}
