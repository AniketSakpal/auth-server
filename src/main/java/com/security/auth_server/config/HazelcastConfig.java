package com.security.auth_server.config;

import com.hazelcast.client.HazelcastClient;
import com.hazelcast.client.config.ClientConfig;
import com.hazelcast.core.HazelcastInstance;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class HazelcastConfig {

    @Bean
    public ClientConfig hazelcastConfiguration() {
        ClientConfig clientConfig = new ClientConfig();
        clientConfig.getNetworkConfig().addAddress("localhost:5701");
        return clientConfig;
    }

    @Bean
    public HazelcastInstance hazelcastInstance() {
        return HazelcastClient.newHazelcastClient(hazelcastConfiguration());
    }
}
