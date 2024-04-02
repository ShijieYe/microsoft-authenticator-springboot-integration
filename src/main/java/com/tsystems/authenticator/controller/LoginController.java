package com.tsystems.authenticator.controller;

import com.tsystems.authenticator.service.impl.MicrosoftAuth;
import com.tsystems.authenticator.util.TwoFactorAuthUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.Date;

@RestController
@RequiredArgsConstructor
@RequestMapping("/login")
public class LoginController {

    private final MicrosoftAuth microsoftAuth;

    // Secret key for QR code generation and verification, should be kept secret in database
    private final String secretKey = "3KPXCDD2TAXI3B3FLUOHDQGWK6CIEMJZ";

    @PutMapping
    public String loginForm(@RequestParam String username, @RequestParam String password) {
        if (username.equals("admin") && password.equals("password")) {
            return microsoftAuth.getSecretKey();
        } else {
            return "Invalid username or password";
        }
    }
    @GetMapping("/secret")
    public String getQrCode(@RequestParam String username) {
        return TwoFactorAuthUtil.getQrCode(username, secretKey);
    }

    @PostMapping("/verify")
    public String verifyCode(@RequestParam long code) {
        Date now = new Date();
        boolean isValid = microsoftAuth.checkCode(secretKey, code, now.getTime());
        if (isValid) {
            return "Login successful";
        }
        return "Login failed";
    }

}
