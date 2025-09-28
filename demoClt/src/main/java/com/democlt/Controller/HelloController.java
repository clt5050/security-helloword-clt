package com.democlt.Controller;


import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
/**
 * 测试接口
 */
@RestController
public class HelloController {
     /**
     * 测试接口
     * @return "Hello World"
     */
    @GetMapping("/hello")
    public String helloWorld() {
        return "Hello World";
    }

}
