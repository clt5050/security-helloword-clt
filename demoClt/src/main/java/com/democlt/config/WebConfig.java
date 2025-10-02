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
        // 配置日志拦截器，拦截所有请求但排除错误页面请求
        registry.addInterceptor(logInterceptor)//将自定义的logInterceptor注册到系统中。
                .addPathPatterns("/**")//定义拦截范围为 “所有请求”（/**是 Ant 风格路径匹配，代表任意层级的任意路径）。
                .excludePathPatterns("/error");//排除不需要拦截的路径
    }

}
