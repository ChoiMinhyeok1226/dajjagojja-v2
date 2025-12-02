package com.multi.travel.auth.user;

/*
 * Please explain the class!!!
 *
 * @filename    : CustomUser
 * @author      : Choi MinHyeok
 * @since       : 25. 12. 1. 월요일
 */


import com.multi.travel.auth.user.enums.UserStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;


@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CustomUser implements UserDetails {
    private String email;
    private String password;
    private String name;
    private UserStatus status;
    private Collection<? extends GrantedAuthority> authorities;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.email;
    }
}
