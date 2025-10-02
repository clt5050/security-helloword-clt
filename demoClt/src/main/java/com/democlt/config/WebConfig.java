package com.democlt.config;


import com.democlt.interceptor.LogInterceptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * 拦截器的使用示例
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {
    // 注入日志拦截器
    @Autowired
    private LogInterceptor logInterceptor;

    /**
     * 添加拦截器配置
     * InterceptorRegistry registry：拦截器注册表对象，用于注册自定义拦截器并配置其拦截规则。
     * @param registry 拦截器注册器，用于注册和配置拦截器
     */
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(logInterceptor)
                .addPathPatterns("/**")
                .excludePathPatterns("/error");
    }

}
