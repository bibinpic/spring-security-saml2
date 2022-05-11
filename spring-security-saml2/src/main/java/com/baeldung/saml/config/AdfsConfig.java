package com.baeldung.saml.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import com.baeldung.saml.authentication.SAMLUserService;

import static org.springframework.security.extensions.saml2.config.SAMLConfigurer.saml;

@EnableWebSecurity
@Configuration
@Order(2)
public class AdfsConfig extends WebSecurityConfigurerAdapter {

  @Value("${saml.adfs.metadata}")
  private String adfsMetdata;

  @Value("${saml.sso.host}")
  private String adfsHost;
  

  @Value("${server.ssl.key-store}")
  private String keyStoreFile;

  @Value("${server.ssl.key-store-password}")
  private String keyStorePassword;

  @Value("${server.ssl.key-alias}")
  private String keyStoreAlias;

  @Autowired
  private SAMLUserService userService;
 
  @Override
  protected void configure( HttpSecurity http) throws Exception {
    //@formatter:off 
	  http
      .csrf()
      .and().antMatcher("/adfs").authorizeRequests()
        .antMatchers("/saml/**").permitAll()
        .anyRequest()
            .authenticated()
        .and()
      .apply(saml())
        .userDetailsService(userService).serviceProvider().entityId("Test2")
        .protocol("https")
        .hostname(adfsHost )
        .basePath("/")
        .keyStore()
          .storeFilePath(keyStoreFile)
          .keyPassword(keyStorePassword)
          .keyname(keyStoreAlias)
        . and()
      .and()
      .identityProvider()
        .metadataFilePath(adfsMetdata).discoveryEnabled(false);   
  }
  
}
