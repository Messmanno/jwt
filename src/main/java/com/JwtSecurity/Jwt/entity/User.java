package com.JwtSecurity.Jwt.entity;


import jakarta.persistence.*;
import lombok.*;



@AllArgsConstructor
@NoArgsConstructor
@Builder
@Entity
@Setter
@Getter
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;
    private String password;
    private String role;



}
