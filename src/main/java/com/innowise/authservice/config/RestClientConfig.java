package com.innowise.authservice.config;

import com.innowise.authservice.service.JwtService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

@Configuration
public class RestClientConfig {

    @Bean
    public RestClient userServiceRestClient(
            @Value("${user-service.base-url}") String baseUrl,
            @Value("${user-service.timeout-ms}") long timeOutMs,
            JwtService jwtService) {

        var requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout((int) timeOutMs);
        requestFactory.setReadTimeout((int) timeOutMs);

        return RestClient.builder()
                .baseUrl(baseUrl)
                .requestFactory(requestFactory)
                .requestInterceptor((request, body, execution) -> {
                    request.getHeaders().setBearerAuth(jwtService.generateServiceToken());
                    return execution.execute(request, body);
                })
                .build();
    }
}
