package com.camline.products.ecap.external.service.handler.server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages= {"com.camline.products.ecap.external.service.handler"})
public class SimpleRestApisApplication {
	public static void main(String[] args) {
		SpringApplication.run(SimpleRestApisApplication.class, args);
	}
}
