package br.com.idb.idbauth.docs;

import org.springframework.context.annotation.Configuration;

import br.com.idb.idbcore.docs.BaseSwaggerConfig;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

/**
 * @author William Suane
 */
@Configuration
@EnableSwagger2
public class SwaggerConfig extends BaseSwaggerConfig {
    public SwaggerConfig() {
        super("br.com.idb.idbauth.endpoint.controller");
    }
}
