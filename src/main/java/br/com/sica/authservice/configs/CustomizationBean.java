package br.com.sica.authservice.configs;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.boot.web.servlet.server.ConfigurableServletWebServerFactory;
import org.springframework.stereotype.Component;

@Component
public class CustomizationBean implements
        WebServerFactoryCustomizer<ConfigurableServletWebServerFactory> {

    @Value("${spring.datasource.url}")
    private String postgresUrl;

    @Override
    public void customize(ConfigurableServletWebServerFactory container) {
        //container.setPort(8083);
        System.out.println("\n## postgresUrl: " + postgresUrl + "##\n");
    }
}
