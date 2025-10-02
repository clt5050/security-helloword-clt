启动项目：运行DemoApplication.java。

获取 JWT 令牌：
      发送 POST 请求到http://localhost:8080/login，参数：
      username=test&password=123456
      响应示例：JWT令牌: eyJhbGciOiJIUzUxMiJ9...（实际令牌）。
访问 Hello 接口：
      发送 GET 请求到http://localhost:8080/hello，请求头添加：
      Authorization: Bearer eyJhbGciOiJIUzUxMiJ9...（替换为实际令牌）
      响应：Hello World。
      验证拦截器：
控制台会输出拦截器记录的日志（IP、路径、耗时等）。
