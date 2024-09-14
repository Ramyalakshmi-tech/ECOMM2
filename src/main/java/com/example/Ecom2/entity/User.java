package com.example.Ecom2.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.HashSet;
import java.util.Set;
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name="users")
public class User {
@Id
@GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

@Column(nullable = false,unique = true)
    private String username;
@Column(nullable = false,unique = true)
    private String email;
@Column(nullable = false,unique = true)
    private String password;

@ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles=new HashSet<>();
}