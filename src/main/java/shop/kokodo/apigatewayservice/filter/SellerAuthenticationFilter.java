package shop.kokodo.apigatewayservice.filter;

import io.jsonwebtoken.JwtException;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpHeaders;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;
import shop.kokodo.apigatewayservice.utils.JwtTokenUtil;

@Slf4j
@Component
public class SellerAuthenticationFilter extends AbstractGatewayFilterFactory<SellerAuthenticationFilter.Config> {

    private final JwtTokenUtil jwtTokenUtil;

    String TOKEN_PREFIX = "Bearer ";

    @Value("${token.seller.secret}")
    private String secret;

    public SellerAuthenticationFilter(JwtTokenUtil jwtTokenUtil) {
        super(Config.class);
        this.jwtTokenUtil = jwtTokenUtil;
    }

    public static class Config {}

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            ServerHttpRequest req = exchange.getRequest();

            String header = req.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
            String accessToken = (header != null && header.startsWith(TOKEN_PREFIX)) ? header.replace(TOKEN_PREFIX,"") : null;

            // Request Header 에 Access Token (Authorization) 이 담긴 경우
            if (!ObjectUtils.isEmpty(accessToken)) {
                // Access Token 이 만료된 경우
                if(jwtTokenUtil.isTokenExpired(accessToken, secret)) {
                    throw new JwtException("토큰 만료");
                }

                if (jwtTokenUtil.isInvalidToken(accessToken, secret)) {
                    throw new JwtException("유효하지 않은 토큰");
                }
            }

            log.debug("JWT 유효성 검사 완료");
            return chain.filter(exchange);
        });
    }
}