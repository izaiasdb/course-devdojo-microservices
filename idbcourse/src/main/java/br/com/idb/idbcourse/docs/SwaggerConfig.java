package br.com.idb.idbcourse.docs;

import org.springframework.context.annotation.Configuration;

import br.com.idb.idbcore.docs.BaseSwaggerConfig;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

@Configuration
@EnableSwagger2
public class SwaggerConfig extends BaseSwaggerConfig {
    public SwaggerConfig() {
        super("br.com.idb.idbcourse.endpoint.controller");
    }
}
