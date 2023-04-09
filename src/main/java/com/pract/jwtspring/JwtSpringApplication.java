package com.pract.jwtspring;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;

@SpringBootApplication
@EnableMongoRepositories
public class JwtSpringApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtSpringApplication.class, args);
    }

}
