package com.fitsight.fsarchgateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;

@EnableZuulProxy
@SpringBootApplication
public class FsArchGatewayApplication {

	public static void main(String[] args) {
		SpringApplication.run(FsArchGatewayApplication.class, args);
	}
}
