package br.com.idb.idbauth;

import br.com.idb.idbcore.property.JwtConfiguration;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication
@EnableConfigurationProperties(value = JwtConfiguration.class) // Aula 07
@EnableEurekaClient
@EntityScan({"br.com.idb.idbcore.model"})
@EnableJpaRepositories({"br.com.idb.idbcore.repository"})
@ComponentScan("br.com.idb")
public class IdbAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(IdbAuthApplication.class, args);
    }

}
