package com.rsr.api_gateway.security.filter;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.annotation.Order;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

@Component
@Order(0)
public class UserIdFilterShoppingCart extends AbstractGatewayFilterFactory<UserIdFilterShoppingCart.Config> {

    public UserIdFilterShoppingCart() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication != null && authentication.getPrincipal() instanceof Jwt) {
                Jwt jwt = (Jwt) authentication.getPrincipal();
                String userId = jwt.getClaimAsString("sub");

                // Add the userId to the path
                ServerHttpRequest request = exchange.getRequest().mutate()
                        .path(exchange.getRequest().getPath().toString().replace("/shopping-cart", "/shopping-cart/" + userId))
                        .build();
                return chain.filter(exchange.mutate().request(request).build());
            }
            return chain.filter(exchange);
        };
    }

    public static class Config {
        // Put configuration properties here if needed
    }
}
