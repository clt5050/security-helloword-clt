package com.democlt.interceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * 日志拦截器
 */
@Component
public class LogInterceptor implements HandlerInterceptor {
    private long startTime;
    /**
     * 请求处理前执行的方法，在请求被处理之前调用
     * @param request HTTP请求对象，包含客户端请求信息
     * @param response HTTP响应对象，用于向客户端发送响应
     * @param handler 处理器对象，表示将要执行的处理器方法
     * @return boolean 返回true表示放行请求，继续执行后续处理；返回false表示拦截请求，不再继续执行
     */
    @Override
    public boolean preHandle(HttpServletRequest request,
                             HttpServletResponse response, Object handler) {
        startTime = System.currentTimeMillis();
        System.out.println("=== 开始请求 ===");
        System.out.println("访问IP: " + request.getRemoteAddr());
        System.out.println("请求路径: " + request.getRequestURI());
        System.out.println("请求方法: " + request.getMethod());
        return true;
    }

    /**
     * 请求处理完成后执行的回调方法，用于记录请求处理的耗时和响应状态
     *
     * @param request  HTTP请求对象，包含客户端发送的请求信息
     * @param response HTTP响应对象，用于向客户端发送响应数据
     * @param handler  处理当前请求的处理器对象
     * @param ex       请求处理过程中抛出的异常，如果没有异常则为null
     */

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response,
                                Object handler, Exception ex) {
        long endTime = System.currentTimeMillis();
        System.out.println("请求耗时: " + (endTime - startTime) + "ms");
        System.out.println("响应状态: " + response.getStatus());
        System.out.println("=== 结束请求 ===");
    }


}
