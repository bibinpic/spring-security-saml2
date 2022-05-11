package com.baeldung.saml.authentication;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class SAMLUserService implements SAMLUserDetailsService {


  @Override
  public String loadUserBySAML(SAMLCredential credential) throws UsernameNotFoundException {
    String user = credential.getNameID().getValue();


    return user;
  }

  private List<GrantedAuthority> getAuthorities(String role) {
    List<GrantedAuthority> list = new ArrayList<GrantedAuthority>();
    list.add(new SimpleGrantedAuthority(role));
    return list;
  }
}
