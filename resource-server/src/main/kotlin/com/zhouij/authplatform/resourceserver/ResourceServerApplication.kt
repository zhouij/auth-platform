
package com.zhouij.authplatform.resourceserver

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.autoconfigure.domain.EntityScan
import org.springframework.boot.runApplication
import org.springframework.data.jpa.repository.config.EnableJpaRepositories

@SpringBootApplication
@EntityScan(basePackages = ["com.zhouij.authplatform.resourceserver.domain"])
@EnableJpaRepositories(basePackages = ["com.zhouij.authplatform.resourceserver.repository"])
class ResourceServerApplication
fun main(args: Array<String>) { runApplication<ResourceServerApplication>(*args) }
