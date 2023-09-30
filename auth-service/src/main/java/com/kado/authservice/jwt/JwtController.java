package com.kado.authservice.jwt;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

@RestController
@RequiredArgsConstructor
public class JwtController {

    private final RsaUtils rsaUtils;

    @GetMapping("/public-keys")
    public ResponseEntity<Object> getPublicKeys() {
        try {
            PublicKey publicKey = rsaUtils.getPublicKey();
            if (publicKey != null) {
                JWK jwk = new RSAKey.Builder((RSAPublicKey) publicKey)
                        .keyID("key-id")
                        .build();
                JWKSet jwkSet = new JWKSet(jwk);
                return ResponseEntity.ok(jwkSet.toJSONObject());
            } else {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Public key not available");
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error fetching public key");
        }
    }
}

