package com.appsdeveloperblog.ws.api.ApiGateway.filter;

import com.appsdeveloperblog.ws.api.ApiGateway.util.JwtUtil;
import com.appsdeveloperblog.ws.api.ApiGateway.validator.RouteValidator;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import org.apache.http.auth.AuthenticationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;

import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;
import org.springframework.http.server.reactive.ServerHttpRequest.Builder;

import java.io.ObjectInputFilter;
import java.net.URI;
import java.util.function.Consumer;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.NameConfig> {
    private final RouteValidator routeValidator;
    private final JwtUtil jwtUtil;
    @Autowired
    public AuthenticationFilter(RouteValidator routeValidator, JwtUtil jwtUtil){
        super(NameConfig.class);
        this.routeValidator = routeValidator;
        this.jwtUtil = jwtUtil;

    }


    @Override
    public GatewayFilter apply(NameConfig nameConfig) {
        return ((exchange, chain) -> {
            if (routeValidator.isSecured.test(exchange.getRequest())) {
                if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                    throw new RuntimeException("Missing authorization header");
                }

                String authHeader = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
                if (authHeader != null && authHeader.startsWith("Bearer ")) {
                    authHeader = authHeader.substring(7);
                }
                try {
                    if(jwtUtil.validateToken(authHeader)){
                        return chain.filter(exchange);
                    }
                    else{
                        throw new AuthenticationException("Token not valid");


                    }
                } catch (Exception e) {
                    System.out.println("Invalid access...!"+ e.getClass());
                    throw new RuntimeException("Unauthorized access to the application" + e.getClass());
                }
            }
            return chain.filter(exchange);
        });
    }


}
