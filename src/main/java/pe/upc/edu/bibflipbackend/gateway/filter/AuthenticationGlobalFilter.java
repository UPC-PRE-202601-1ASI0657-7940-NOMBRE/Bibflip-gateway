package pe.upc.edu.bibflipbackend.gateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;

@Component
public class AuthenticationGlobalFilter implements GlobalFilter, Ordered {

    private static final List<String> EXCLUDED_PATHS = List.of(
            "/api/v1/authentication/sign-in",
            "/api/v1/authentication/sign-up",
            "/api/v1/roles"
    );

    @Value("${authorization.jwt.secret}")
    private String secret;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange,
                             org.springframework.cloud.gateway.filter.GatewayFilterChain chain) {

        String path = exchange.getRequest().getURI().getPath();

        if (exchange.getRequest().getMethod() == org.springframework.http.HttpMethod.OPTIONS) {
            return chain.filter(exchange);
        }

        if (EXCLUDED_PATHS.stream().anyMatch(path::equals)) {
            return chain.filter(exchange);
        }

        HttpHeaders headers = exchange.getRequest().getHeaders();
        String authHeader = headers.getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = authHeader.substring(7);

        if (!validateToken(token)) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        return chain.filter(exchange);
    }

    private boolean validateToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .setSigningKey(secret.getBytes(StandardCharsets.UTF_8))
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            return !claims.getExpiration().before(new Date());

        } catch (SignatureException | IllegalArgumentException e) {
            return false;
        }
    }

    @Override
    public int getOrder() {
        return -1;
    }
}