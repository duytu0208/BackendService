package com.be.english.auth.db;


import com.be.english.common.AbstractEntity;
import jakarta.persistence.*;
import lombok.*;

@Builder
@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "app_signup")
public class AuthEntity extends AbstractEntity<Long> {
    @Column(name = "user_name")
    private String username;

    @Column(name = "password")
    private String password;

    @Column(name = "status")
    @Enumerated(EnumType.STRING)
    private Status status;

    //    @Column(name = "signup_data", columnDefinition = "jsonb", nullable = false)
    @Column(name = "signup_data")
    private String signupData;
}
