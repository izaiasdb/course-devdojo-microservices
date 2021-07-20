package br.com.idb.idbcourse;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import br.com.idb.idbcore.property.JwtConfiguration;

@SpringBootApplication
@EnableConfigurationProperties(value = JwtConfiguration.class) // Aula 08
@EntityScan({"br.com.idb.idbcore.model"})
@EnableJpaRepositories({"br.com.idb.idbcore.repository"})
@ComponentScan("br.com.idb") // Aula 08
public class IdbCourseApplication {

	public static void main(String[] args) {
		SpringApplication.run(IdbCourseApplication.class, args);
	}

}
