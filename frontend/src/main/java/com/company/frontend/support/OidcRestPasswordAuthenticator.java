package com.company.frontend.support;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jmix.oidc.user.DefaultJmixOidcUser;
import io.jmix.restds.exception.InvalidRefreshTokenException;
import io.jmix.restds.exception.RestDataStoreAccessException;
import io.jmix.restds.impl.RestPasswordAuthenticator;
import io.jmix.restds.impl.RestTokenHolder;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Scope;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Component("restds_OidcRestPasswordAuthenticator")
@Scope("prototype")
public class OidcRestPasswordAuthenticator extends RestPasswordAuthenticator {
    private static final Logger log = LoggerFactory.getLogger(OidcRestPasswordAuthenticator.class);
    private final ObjectMapper objectMapper = new ObjectMapper();
    private RestClient client;
    private String dataStoreName;
    private String clientId;
    private String clientSecret;
    @Autowired
    private RestTokenHolder tokenHolder;
    @Autowired
    private ApplicationContext applicationContext;

    public OidcRestPasswordAuthenticator() {
    }

    public void setDataStoreName(String name) {
        this.dataStoreName = name;
        this.initClient();
    }

    private void initClient() {
        Environment environment = this.applicationContext.getEnvironment();
        String baseUrl = environment.getRequiredProperty(this.dataStoreName + ".baseUrl");
        this.clientId = environment.getRequiredProperty(this.dataStoreName + ".clientId");
        this.clientSecret = environment.getRequiredProperty(this.dataStoreName + ".clientSecret");
        this.client = RestClient.builder().baseUrl(baseUrl).requestInterceptor(new LoggingClientHttpRequestInterceptor()).build();
    }

    public ClientHttpRequestInterceptor getAuthenticationInterceptor() {
        return new RetryingClientHttpRequestInterceptor();
    }

    public void authenticate(String username, String password) {
        MultiValueMap<String, String> params = new LinkedMultiValueMap();
        params.add("grant_type", "password");
        params.add("username", username);
        params.add("password", password);

        ResponseEntity authResponse;
        try {
            authResponse = ((RestClient.RequestBodySpec)((RestClient.RequestBodySpec)this.client.post().uri("/oauth2/token", new Object[0])).headers((httpHeaders) -> {
                httpHeaders.setBasicAuth(this.clientId, this.clientSecret);
                httpHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            })).body(params).retrieve().onStatus((statusCode) -> {
                return statusCode == HttpStatus.BAD_REQUEST;
            }, (request, response) -> {
                throw new BadCredentialsException(IOUtils.toString(response.getBody(), StandardCharsets.UTF_8));
            }).toEntity(String.class);
        } catch (ResourceAccessException var9) {
            ResourceAccessException e = var9;
            throw new RestDataStoreAccessException(this.dataStoreName, e);
        }

        try {
            JsonNode rootNode = this.objectMapper.readTree((String)authResponse.getBody());
            String accessToken = rootNode.get("access_token").asText();
            if (!rootNode.has("refresh_token")) {
                throw new IllegalStateException("Refresh token is not provided. Add 'refresh_token' to authorization server grant types.");
            } else {
                String refreshToken = rootNode.get("refresh_token").asText();
                this.tokenHolder.setTokens(accessToken, refreshToken);
            }
        } catch (JsonProcessingException var8) {
            JsonProcessingException e = var8;
            throw new RuntimeException(e);
        }
    }

    private String authenticate(String refreshToken) {
        MultiValueMap<String, String> params = new LinkedMultiValueMap();
        params.add("grant_type", "refresh_token");
        params.add("refresh_token", refreshToken);

        ResponseEntity authResponse;
        try {
            authResponse = ((RestClient.RequestBodySpec)((RestClient.RequestBodySpec)this.client.post().uri("1", new Object[0])).headers((httpHeaders) -> {
                httpHeaders.setBasicAuth(this.clientId, this.clientSecret);
                httpHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            })).body(params).retrieve().onStatus((statusCode) -> {
                return statusCode == HttpStatus.BAD_REQUEST;
            }, (request, response) -> {
                throw new InvalidRefreshTokenException(this.dataStoreName);
            }).toEntity(String.class);
        } catch (ResourceAccessException var7) {
            ResourceAccessException e = var7;
            throw new RestDataStoreAccessException(this.dataStoreName, e);
        }

        try {
            JsonNode rootNode = this.objectMapper.readTree((String)authResponse.getBody());
            String accessToken = rootNode.get("access_token").asText();
            this.tokenHolder.setTokens(accessToken, refreshToken);
            return accessToken;
        } catch (JsonProcessingException var6) {
            JsonProcessingException e = var6;
            throw new RuntimeException(e);
        }
    }

    private String getAccessToken() {
        DefaultJmixOidcUser principal = (DefaultJmixOidcUser) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        OidcIdToken idToken = principal.getDelegate().getIdToken();
        String accessToken = idToken.getTokenValue();
        if (accessToken == null) {
            throw new IllegalStateException("Access token is not stored. Authenticate with username and password first.");
        } else {
            return accessToken;
        }
    }

    private String getAccessTokenByRefreshToken() {
        String refreshToken = this.tokenHolder.getRefreshToken();
        if (refreshToken == null) {
            throw new IllegalStateException("Refresh token is not stored. Authenticate with username and password first.");
        } else {
            String accessToken = this.authenticate(refreshToken);
            return accessToken;
        }
    }

    private static class LoggingClientHttpRequestInterceptor implements ClientHttpRequestInterceptor {
        private LoggingClientHttpRequestInterceptor() {
        }

        public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {
            log.debug("Request: {} {}", request.getMethod(), request.getURI());
            ClientHttpResponse response = execution.execute(request, body);
            log.debug("Response: {}", response.getStatusCode());
            return response;
        }
    }

    private class RetryingClientHttpRequestInterceptor implements ClientHttpRequestInterceptor {
        private RetryingClientHttpRequestInterceptor() {
        }

        public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {
            request.getHeaders().setBearerAuth(OidcRestPasswordAuthenticator.this.getAccessToken());
            ClientHttpResponse response = execution.execute(request, body);
            if (response.getStatusCode().is4xxClientError() && response.getStatusCode().value() == 401) {
                request.getHeaders().setBearerAuth(OidcRestPasswordAuthenticator.this.getAccessTokenByRefreshToken());
                response = execution.execute(request, body);
            }

            return response;
        }
    }
}
