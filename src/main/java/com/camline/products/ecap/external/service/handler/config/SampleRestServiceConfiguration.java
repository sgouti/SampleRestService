package com.camline.products.ecap.external.service.handler.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

@Configuration
@PropertySource(value = "file:./properties/sample-rest-service.properties", ignoreResourceNotFound = true)
public class SampleRestServiceConfiguration {
	
}
