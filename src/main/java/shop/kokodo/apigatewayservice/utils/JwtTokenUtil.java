package shop.kokodo.apigatewayservice.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import java.io.Serializable;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class JwtTokenUtil implements Serializable {

    private static final Long serialVersionUID = -2550185165626007488L;

    public Boolean isTokenExpired(String token, String secret) {
        final Date expiration = getExpirationDateFromToken(token, secret);
        return expiration.before(new Date());
    }

    public Date getExpirationDateFromToken(String token, String secret) {
        return getClaimFromToken(token, secret, Claims::getExpiration);
    }

    public Boolean isInvalidToken(String token, String secret) {
        try {
            getAllClaimsFromToken(token, secret);
        } catch (IllegalArgumentException | SignatureException e) {
            e.printStackTrace();
            return true;
        }
        return false;
    }

    public <T> T getClaimFromToken(String token, String secret, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token, secret);
        return claimsResolver.apply(claims);
    }

    private Claims getAllClaimsFromToken(String token, String secret) {
        try {
            return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
        }
        catch (ExpiredJwtException e) {
            log.error("JWT 토큰 만료.");
            throw e;
        }
        catch (SignatureException e) {
            log.error("JWT 토큰 서명 검증 실패. 암복호화 secret 불일치.");
            throw e;
        }
    }
}
