package br.com.idb.idbgateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.context.annotation.ComponentScan;

import br.com.idb.idbcore.property.JwtConfiguration;

@SpringBootApplication
@EnableZuulProxy
@EnableEurekaClient
@EnableConfigurationProperties(value = JwtConfiguration.class) // Aula 07
@ComponentScan("br.com.idb")
public class IdbGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(IdbGatewayApplication.class, args);
    }

}