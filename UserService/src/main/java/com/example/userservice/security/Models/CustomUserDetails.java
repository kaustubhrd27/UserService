package com.example.userservice.security.Models;

import com.example.userservice.Models.Role;
import com.example.userservice.Models.User;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@JsonDeserialize
public class CustomUserDetails implements UserDetails {

    private String password; // password
    private String username; // email
    private boolean accountNonExpired;
    private boolean accountNonLocked;
    private boolean credentialsNonExpired;
    private boolean enabled;
    //Basically List<Roles>
    private List<CustomGrantedAuthority> authorities;
    private Long userId;
    private String userName;

    public CustomUserDetails(){}
    public CustomUserDetails(User user) {
        this.username = user.getEmail();
        this.password = user.getHashedPassword();
        this.accountNonExpired = true;
        this.credentialsNonExpired = true;
        this.accountNonLocked = true;
        this.enabled = true;
        this.authorities = new ArrayList<>();
        this.userId = user.getId();
        this.userName = user.getName();

        for (Role role : user.getRoles()) {
            authorities.add(new CustomGrantedAuthority(role));
        }
    }

    public Long getUserId() {
        return userId;
    }

    public String getUserName() {
        return userName;
    }
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
}
