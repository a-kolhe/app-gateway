package com.working.app_gateway.filter;

import java.nio.charset.StandardCharsets;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.working.app_gateway.util.JwtUtil;
import com.working.app_gateway.util.RouteValidator;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;


@Component
@Slf4j
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {
	@Autowired
	private RouteValidator validator;

	// @Autowired
//    private RestTemplate template;
	@Autowired
	private JwtUtil jwtUtil;

	private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(AuthenticationFilter.class);

	public AuthenticationFilter() {
		super(Config.class);
	}

	@Override
	public GatewayFilter apply(Config config) {
		return ((exchange, chain) -> {
			if (validator.isSecured.test(exchange.getRequest())) {
				// header contains token or not
				if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
					throw new RuntimeException("missing authorization header");
				}

				String authHeader = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
				if (authHeader != null && authHeader.startsWith("Bearer ")) {
					authHeader = authHeader.substring(7);
				}
				try {
//                    //REST call to AUTH service
//                    template.getForObject("http://IDENTITY-SERVICE//validate?token" + authHeader, String.class);
					jwtUtil.validateToken(authHeader);
                    List<String> roles = jwtUtil.getRoles(authHeader);
                    String path = exchange.getRequest().getPath().toString();
                    if (!hasRequiredRole(path, roles)) {
                        log.warn("Access denied to path '{}' for roles {}", path, roles);
                        return unauthorizedResponse(exchange, "Access denied for your role");
                    }
                    log.info("Authorized request for path '{}' with roles: {}", path, roles);

				} catch (ExpiredJwtException  e) {
				    log.warn("JWT expired: {}", e.getMessage());
//					System.out.println("invalid access...!");
				    return unauthorizedResponse(exchange, "Token expired");
				}catch (JwtException  e2) {
				    log.warn("JWT invalid: {}", e2.getMessage());
				    return unauthorizedResponse(exchange, "Invalid token");

					// TODO: handle exception
				}catch (Exception e3) {
					log.error("Exception : {}",e3.getMessage(),e3);
				}
			}
			return chain.filter(exchange);
		});
	}
	
	private Mono<Void> unauthorizedResponse(ServerWebExchange exchange, String message) {
	    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
	    DataBuffer buffer = exchange.getResponse().bufferFactory()
	        .wrap(("{\"error\":\"" + message + "\"}").getBytes(StandardCharsets.UTF_8));
	    exchange.getResponse().getHeaders().add("Content-Type", "application/json");
	    return exchange.getResponse().writeWith(Mono.just(buffer));
	}

	   private boolean hasRequiredRole(String path, List<String> roles) {
	        if (path.startsWith("/partner")) return roles.contains("ROLE_PARTNER");
	        if (path.startsWith("/user")) return roles.contains("ROLE_USER");
	        return true; // Allow all other paths
	    }

	public static class Config {

	}
}
