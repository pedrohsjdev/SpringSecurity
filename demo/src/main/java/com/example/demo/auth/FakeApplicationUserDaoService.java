package com.example.demo.auth;

import com.example.demo.student.Student;
import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.example.demo.security.ApplicationUserRole.*;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao{
    @Autowired
    private final PasswordEncoder passwordEncoder;

    public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUsers()
                .stream().filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers(){
        List<ApplicationUser> applicationUsers = Lists.newArrayList(
                new ApplicationUser(
                        STUDENT.getGrantedAuthority(),
                        "anakin",
                        passwordEncoder.encode("0000"),
                        true,
                        true,
                        true,
                        true
                ),new ApplicationUser(
                        ADMINTRAINEE.getGrantedAuthority(),
                        "tom",
                        passwordEncoder.encode("0000"),
                        true,
                        true,
                        true,
                        true
                ),new ApplicationUser(
                        ADMIN.getGrantedAuthority(),
                        "admin",
                        passwordEncoder.encode("0000"),
                        true,
                        true,
                        true,
                        true
                )
        );
        return applicationUsers;
    }
}
