package com.pract.jwtspring.rest;

import com.pract.jwtspring.document.RefreshToken;
import com.pract.jwtspring.document.User;
import com.pract.jwtspring.dto.LoginDto;
import com.pract.jwtspring.dto.SignupDto;
import com.pract.jwtspring.dto.TokenDto;
import com.pract.jwtspring.jwt.JwtHelper;
import com.pract.jwtspring.repository.RefreshTokenRepository;
import com.pract.jwtspring.repository.UserRepository;
import com.pract.jwtspring.service.UserService;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import javax.validation.Valid;

@Log4j2
@RestController
@RequestMapping("/api/auth")
public class AuthRest {
    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
    RefreshTokenRepository refreshTokenRepository;
    @Autowired
    UserRepository userRepository;
    @Autowired
    JwtHelper jwtHelper;
    @Autowired
    PasswordEncoder passwordEncoder;
    @Autowired
    UserService userService;

    @PostMapping("/login")
    @Transactional
    public ResponseEntity<?> login(@Valid @RequestBody LoginDto dto) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(dto.getUsername(), dto.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        User user = (User) authentication.getPrincipal();
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setOwner(user);
        refreshTokenRepository.save(refreshToken);

        String accessToken = jwtHelper.generateAccessToken(user);
        String refreshTokenString = jwtHelper.generateRefreshToken(user, refreshToken);

        return ResponseEntity.ok(new TokenDto(user.getId(), accessToken, refreshTokenString));
    }

    @PostMapping("/signup")
    @Transactional
    public ResponseEntity<?> signup(@Valid @RequestBody SignupDto dto) {
        log.info("dto signup: username: {}", dto.getUsername());
        User user = new User(dto.getUsername(), dto.getEmail(), passwordEncoder.encode(dto.getPassword()));
        userRepository.save(user);
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setOwner(user);
        refreshTokenRepository.save(refreshToken);
        String accessToken = jwtHelper.generateAccessToken(user);
        String refreshTokenString = jwtHelper.generateRefreshToken(user, refreshToken);
        return ResponseEntity.ok(new TokenDto(user.getId(), accessToken, refreshTokenString));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody TokenDto dto) {
        String refreshTokenString = dto.getRefreshToken();
        if (jwtHelper.validateRefreshToken(refreshTokenString) && refreshTokenRepository.
                existsById(jwtHelper.getTokenIdFromRefreshToken(refreshTokenString))) {
            refreshTokenRepository.deleteById(
                    jwtHelper.getTokenIdFromRefreshToken(refreshTokenString));
            return ResponseEntity.ok().build();
        }

        throw new BadCredentialsException("invalid token");
    }

    @PostMapping("/logout-all")
    public ResponseEntity<?> logoutAll(@RequestBody TokenDto dto) {
        String refreshTokenString = dto.getRefreshToken();
        if (jwtHelper.validateRefreshToken(refreshTokenString)
                && refreshTokenRepository.existsById(
                        jwtHelper.getTokenIdFromRefreshToken(refreshTokenString))) {
            refreshTokenRepository.deleteByOwner_Id(
                    jwtHelper.getUserIdFromRefreshToken(refreshTokenString));
            return ResponseEntity.ok().build();
        }

        throw new BadCredentialsException("invalid token");
    }

    @PostMapping("/access-token")
    public ResponseEntity<?> accessToken(@RequestBody TokenDto dto) {
        String refreshTokenString = dto.getRefreshToken();
        if (jwtHelper.validateRefreshToken(refreshTokenString) && refreshTokenRepository
                .existsById(jwtHelper
                        .getTokenIdFromRefreshToken(refreshTokenString))) {
            User user = userService.findById(jwtHelper
                    .getUserIdFromRefreshToken(refreshTokenString));
            String accessToken = jwtHelper.generateAccessToken(user);
            return ResponseEntity.ok(new TokenDto(user.getId(), accessToken, refreshTokenString));
        }
        throw new BadCredentialsException("invalid token");
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestBody TokenDto dto) {
        String refreshTokenString = dto.getRefreshToken();
        if (jwtHelper.validateRefreshToken(refreshTokenString) &&
                refreshTokenRepository
                        .existsById(jwtHelper
                                .getTokenIdFromRefreshToken(refreshTokenString))) {
            refreshTokenRepository
                    .deleteById(jwtHelper.getTokenIdFromRefreshToken(refreshTokenString));

            User user = userService
                    .findById(jwtHelper.getUserIdFromRefreshToken(refreshTokenString));
            RefreshToken refreshToken = new RefreshToken();
            refreshToken.setOwner(user);
            refreshTokenRepository.save(refreshToken);

            String accessToken = jwtHelper.generateAccessToken(user);
            String newRefreshTokenString = jwtHelper
                    .generateRefreshToken(user, refreshToken);
            return ResponseEntity.ok(
                    new TokenDto(user.getId(), accessToken, newRefreshTokenString));
        }
        throw new BadCredentialsException("invalid token");
    }
}
