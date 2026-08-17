package com.zhouij.authplatform.iam

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.scheduling.annotation.EnableScheduling

@SpringBootApplication
@EnableScheduling
class IamServerApplication
fun main(args: Array<String>) { runApplication<IamServerApplication>(*args) }
