# 依赖漏洞与代码漏洞分析报告

- 生成时间：2026-07-17T10:27:41+00:00
- 用户问题：请对 mall-security 模块上传附件执行依赖漏洞与代码漏洞扫描，生成一份完整中文 Markdown 报告。只根据上传内容和已核验漏洞事实给出结论。
- 附件数量：16
- 识别依赖：19 个
- 依赖漏洞：0 条
- 代码漏洞：4 条

## 1. 执行链路

- 读取 pom.xml 与代码附件，提取依赖和代码文件。
- 按依赖组件与版本查询并核验依赖漏洞。
- 在上传源码中定位代码漏洞、具体行号和输入传播路径。
- 分别汇总依赖修复版本，以及代码漏洞的风险片段和修复代码。
- 汇总风险、修复建议和参考链接。
- 生成完整 Markdown 报告并写入报告中心。

## 2. 附件与依赖

- pom.xml（pom）
- mall-security/pom.xml（pom）
- mall-security/src/main/java/com/macro/mall/security/annotation/CacheException.java（code）
- mall-security/src/main/java/com/macro/mall/security/aspect/RedisCacheAspect.java（code）
- mall-security/src/main/java/com/macro/mall/security/component/DynamicAuthorizationManager.java（code）
- mall-security/src/main/java/com/macro/mall/security/component/DynamicSecurityMetadataSource.java（code）
- mall-security/src/main/java/com/macro/mall/security/component/DynamicSecurityService.java（code）
- mall-security/src/main/java/com/macro/mall/security/component/JwtAuthenticationTokenFilter.java（code）
- mall-security/src/main/java/com/macro/mall/security/component/RestAuthenticationEntryPoint.java（code）
- mall-security/src/main/java/com/macro/mall/security/component/RestfulAccessDeniedHandler.java（code）
- mall-security/src/main/java/com/macro/mall/security/config/CommonSecurityConfig.java（code）
- mall-security/src/main/java/com/macro/mall/security/config/IgnoreUrlsConfig.java（code）
- mall-security/src/main/java/com/macro/mall/security/config/RedisConfig.java（code）
- mall-security/src/main/java/com/macro/mall/security/config/SecurityConfig.java（code）
- mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java（code）
- mall-security/src/main/java/com/macro/mall/security/util/SpringUtil.java（code）

### 识别到的依赖

- Maven / org.springframework.boot:spring-boot-starter-actuator @ 3.5.14（pom.xml，置信度 high）
- Maven / org.springframework.boot:spring-boot-starter-aop @ 3.5.14（pom.xml，置信度 high）
- Maven / org.springframework.boot:spring-boot-starter-test @ 3.5.14（pom.xml，置信度 high）
- Maven / cn.hutool:hutool-all @ 5.8.40（pom.xml，置信度 high）
- Maven / org.projectlombok:lombok @ 版本未明确（pom.xml，置信度 high）
- Maven / org.springframework.boot:spring-boot-configuration-processor @ 3.5.14（pom.xml，置信度 high）
- Maven / com.macro.mall:mall-common @ 1.0-SNAPSHOT（mall-security/pom.xml，置信度 high）
- Maven / org.springframework.boot:spring-boot-starter-web @ 3.5.14（mall-security/pom.xml，置信度 high）
- Maven / org.springframework.boot:spring-boot-starter-security @ 3.5.14（mall-security/pom.xml，置信度 high）
- Maven / org.springframework.boot:spring-boot-starter-data-redis @ 3.5.14（mall-security/pom.xml，置信度 high）
- Maven / com.macro.mall @ 版本未明确（mall-security/src/main/java/com/macro/mall/security/aspect/RedisCacheAspect.java，置信度 medium）
- Maven / org.aspectj.lang @ 版本未明确（mall-security/src/main/java/com/macro/mall/security/aspect/RedisCacheAspect.java，置信度 medium）
- Maven / org.slf4j.Logger @ 版本未明确（mall-security/src/main/java/com/macro/mall/security/aspect/RedisCacheAspect.java，置信度 medium）
- Maven / org.slf4j.LoggerFactory @ 版本未明确（mall-security/src/main/java/com/macro/mall/security/aspect/RedisCacheAspect.java，置信度 medium）
- Maven / org.springframework:spring-core @ 版本未明确（mall-security/src/main/java/com/macro/mall/security/aspect/RedisCacheAspect.java，置信度 medium）
- Maven / cn.hutool.core @ 版本未明确（mall-security/src/main/java/com/macro/mall/security/component/DynamicAuthorizationManager.java，置信度 medium）
- Maven / cn.hutool.json @ 版本未明确（mall-security/src/main/java/com/macro/mall/security/component/RestAuthenticationEntryPoint.java，置信度 medium）
- Maven / org.springframework.boot:spring-boot @ 版本未明确（mall-security/src/main/java/com/macro/mall/security/config/CommonSecurityConfig.java，置信度 medium）
- Maven / cn.hutool.jwt @ 版本未明确（mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java，置信度 medium）

## 3. 依赖漏洞（组件与版本）

当前未基于明确组件版本确认漏洞。
另有 10 个依赖版本未明确，未计入漏洞命中；不能据此判定为安全。

## 4. 代码漏洞（文件、行号与修复代码）

### 1. 跨方法外部输入未经规范化写入日志

- 风险类型：跨方法外部输入未经规范化写入日志
- 关联依赖漏洞：未明确
- 关联组件：未明确
- 风险位置：mall-security/src/main/java/com/macro/mall/security/component/JwtAuthenticationTokenFilter.java:44
- 代码范围：第 42-46 行
- 置信度：high
- 修复建议：升级日志组件到已确认的安全版本，并在写入日志前规范化换行符和表达式标记。
- CFG：source 到 sink 经过控制条件：mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:60；mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:81；mall-security/src/main/java/com/macro/mall/security/component/JwtAuthenticationTokenFilter.java:41
- DFG：外部输入 API getHeader source → 调用 substring → 调用 JwtTokenUtil.getUserNameFromToken/1 → 调用 JwtTokenUtil.getPayloadFromToken/1 → 调用 parseToken → 调用 getPayloads → 方法返回值 → 调用 get → 表达式传播 → 赋值到 username → 方法返回值 → 日志输出 sink
- 输入位置：mall-security/src/main/java/com/macro/mall/security/component/JwtAuthenticationTokenFilter.java:40

漏洞代码片段（第 42-46 行，风险点为第 44 行）：
```java
String authToken = authHeader.substring(this.tokenHead.length());// The part after "Bearer "
            String username = jwtTokenUtil.getUserNameFromToken(authToken);
            LOGGER.info("checking username:{}", username);
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
```

修复后的代码：
```java
String safeLogValue = String.valueOf(username)
    .replace("\r", "\\r")
    .replace("\n", "\\n")
    .replace("${", "$ {");
LOGGER.info("checking username:{}", safeLogValue);
```

完整 Source→Sink 路径：
- source：mall-security/src/main/java/com/macro/mall/security/component/JwtAuthenticationTokenFilter.java:40｜外部输入 API getHeader source
  ```
  String authHeader = request.getHeader(this.tokenHeader);
  ```
- dataflow_step：mall-security/src/main/java/com/macro/mall/security/component/JwtAuthenticationTokenFilter.java:42｜调用 substring
  ```
  String authToken = authHeader.substring(this.tokenHead.length());// The part after "Bearer "
  ```
- call：mall-security/src/main/java/com/macro/mall/security/component/JwtAuthenticationTokenFilter.java:43｜调用 JwtTokenUtil.getUserNameFromToken/1
  ```
  String username = jwtTokenUtil.getUserNameFromToken(authToken);
  ```
- call：mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:80｜调用 JwtTokenUtil.getPayloadFromToken/1
  ```
  Map<String, Object> payload = getPayloadFromToken(token);
  ```
- dataflow_step：mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:67｜调用 parseToken
  ```
  return JWTUtil.parseToken(token).getPayloads();
  ```
- dataflow_step：mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:67｜调用 getPayloads
  ```
  return JWTUtil.parseToken(token).getPayloads();
  ```
- cfg_condition：mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:60｜try 异常控制路径
  ```
  try {
  ```
- return：mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:67｜方法返回值
  ```
  return JWTUtil.parseToken(token).getPayloads();
  ```
- dataflow_step：mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:81｜调用 get
  ```
  username = payload != null ? (String) payload.get(CLAIM_KEY_USERNAME) : null;
  ```
- dataflow_step：mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:81｜表达式传播
  ```
  username = payload != null ? (String) payload.get(CLAIM_KEY_USERNAME) : null;
  ```
- cfg_condition：mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:81｜三元条件表达式
  ```
  username = payload != null ? (String) payload.get(CLAIM_KEY_USERNAME) : null;
  ```
- dataflow_step：mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:81｜赋值到 username
  ```
  username = payload != null ? (String) payload.get(CLAIM_KEY_USERNAME) : null;
  ```
- return：mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:85｜方法返回值
  ```
  return username;
  ```
- cfg_condition：mall-security/src/main/java/com/macro/mall/security/component/JwtAuthenticationTokenFilter.java:41｜if 控制条件
  ```
  if (authHeader != null && authHeader.startsWith(this.tokenHead)) {
  ```
- sink：mall-security/src/main/java/com/macro/mall/security/component/JwtAuthenticationTokenFilter.java:44｜日志输出 sink
  ```
  LOGGER.info("checking username:{}", username);
  ```

### 2. 跨方法外部输入未经规范化写入日志

- 风险类型：跨方法外部输入未经规范化写入日志
- 关联依赖漏洞：未明确
- 关联组件：未明确
- 风险位置：mall-security/src/main/java/com/macro/mall/security/component/JwtAuthenticationTokenFilter.java:50
- 代码范围：第 48-52 行
- 置信度：high
- 修复建议：升级日志组件到已确认的安全版本，并在写入日志前规范化换行符和表达式标记。
- CFG：source 到 sink 经过控制条件：mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:60；mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:81；mall-security/src/main/java/com/macro/mall/security/component/JwtAuthenticationTokenFilter.java:41；mall-security/src/main/java/com/macro/mall/security/component/JwtAuthenticationTokenFilter.java:45；mall-security/src/main/java/com/macro/mall/security/component/JwtAuthenticationTokenFilter.java:47
- DFG：外部输入 API getHeader source → 调用 substring → 调用 JwtTokenUtil.getUserNameFromToken/1 → 调用 JwtTokenUtil.getPayloadFromToken/1 → 调用 parseToken → 调用 getPayloads → 方法返回值 → 调用 get → 表达式传播 → 赋值到 username → 方法返回值 → 日志输出 sink
- 输入位置：mall-security/src/main/java/com/macro/mall/security/component/JwtAuthenticationTokenFilter.java:40

漏洞代码片段（第 48-52 行，风险点为第 50 行）：
```java
UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    LOGGER.info("authenticated user:{}", username);
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
```

修复后的代码：
```java
String safeLogValue = String.valueOf(username)
    .replace("\r", "\\r")
    .replace("\n", "\\n")
    .replace("${", "$ {");
LOGGER.info("authenticated user:{}", safeLogValue);
```

完整 Source→Sink 路径：
- source：mall-security/src/main/java/com/macro/mall/security/component/JwtAuthenticationTokenFilter.java:40｜外部输入 API getHeader source
  ```
  String authHeader = request.getHeader(this.tokenHeader);
  ```
- dataflow_step：mall-security/src/main/java/com/macro/mall/security/component/JwtAuthenticationTokenFilter.java:42｜调用 substring
  ```
  String authToken = authHeader.substring(this.tokenHead.length());// The part after "Bearer "
  ```
- call：mall-security/src/main/java/com/macro/mall/security/component/JwtAuthenticationTokenFilter.java:43｜调用 JwtTokenUtil.getUserNameFromToken/1
  ```
  String username = jwtTokenUtil.getUserNameFromToken(authToken);
  ```
- call：mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:80｜调用 JwtTokenUtil.getPayloadFromToken/1
  ```
  Map<String, Object> payload = getPayloadFromToken(token);
  ```
- dataflow_step：mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:67｜调用 parseToken
  ```
  return JWTUtil.parseToken(token).getPayloads();
  ```
- dataflow_step：mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:67｜调用 getPayloads
  ```
  return JWTUtil.parseToken(token).getPayloads();
  ```
- cfg_condition：mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:60｜try 异常控制路径
  ```
  try {
  ```
- return：mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:67｜方法返回值
  ```
  return JWTUtil.parseToken(token).getPayloads();
  ```
- dataflow_step：mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:81｜调用 get
  ```
  username = payload != null ? (String) payload.get(CLAIM_KEY_USERNAME) : null;
  ```
- dataflow_step：mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:81｜表达式传播
  ```
  username = payload != null ? (String) payload.get(CLAIM_KEY_USERNAME) : null;
  ```
- cfg_condition：mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:81｜三元条件表达式
  ```
  username = payload != null ? (String) payload.get(CLAIM_KEY_USERNAME) : null;
  ```
- dataflow_step：mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:81｜赋值到 username
  ```
  username = payload != null ? (String) payload.get(CLAIM_KEY_USERNAME) : null;
  ```
- return：mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:85｜方法返回值
  ```
  return username;
  ```
- cfg_condition：mall-security/src/main/java/com/macro/mall/security/component/JwtAuthenticationTokenFilter.java:41｜if 控制条件
  ```
  if (authHeader != null && authHeader.startsWith(this.tokenHead)) {
  ```
- cfg_condition：mall-security/src/main/java/com/macro/mall/security/component/JwtAuthenticationTokenFilter.java:45｜if 控制条件
  ```
  if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
  ```
- cfg_condition：mall-security/src/main/java/com/macro/mall/security/component/JwtAuthenticationTokenFilter.java:47｜if 控制条件
  ```
  if (jwtTokenUtil.validateToken(authToken, userDetails)) {
  ```
- sink：mall-security/src/main/java/com/macro/mall/security/component/JwtAuthenticationTokenFilter.java:50｜日志输出 sink
  ```
  LOGGER.info("authenticated user:{}", username);
  ```

### 3. 跨方法外部输入未经规范化写入日志

- 风险类型：跨方法外部输入未经规范化写入日志
- 关联依赖漏洞：未明确
- 关联组件：未明确
- 风险位置：mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:63
- 代码范围：第 61-65 行
- 置信度：high
- 修复建议：升级日志组件到已确认的安全版本，并在写入日志前规范化换行符和表达式标记。
- CFG：source 到 sink 经过控制条件：mall-security/src/main/java/com/macro/mall/security/component/JwtAuthenticationTokenFilter.java:41；mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:79；mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:60；mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:62
- DFG：外部输入 API getHeader source → 调用 substring → 调用 JwtTokenUtil.getUserNameFromToken/1 → 调用 JwtTokenUtil.getPayloadFromToken/1 → 日志输出 sink
- 输入位置：mall-security/src/main/java/com/macro/mall/security/component/JwtAuthenticationTokenFilter.java:40

漏洞代码片段（第 61-65 行，风险点为第 63 行）：
```java
// 验证token签名
            if (!JWTUtil.verify(token, getSigningKey())) {
                LOGGER.info("JWT签名验证失败:{}", token);
                return null;
            }
```

修复后的代码：
```java
String safeLogValue = String.valueOf(token)
    .replace("\r", "\\r")
    .replace("\n", "\\n")
    .replace("${", "$ {");
LOGGER.info("JWT签名验证失败:{}", safeLogValue);
```

完整 Source→Sink 路径：
- source：mall-security/src/main/java/com/macro/mall/security/component/JwtAuthenticationTokenFilter.java:40｜外部输入 API getHeader source
  ```
  String authHeader = request.getHeader(this.tokenHeader);
  ```
- dataflow_step：mall-security/src/main/java/com/macro/mall/security/component/JwtAuthenticationTokenFilter.java:42｜调用 substring
  ```
  String authToken = authHeader.substring(this.tokenHead.length());// The part after "Bearer "
  ```
- cfg_condition：mall-security/src/main/java/com/macro/mall/security/component/JwtAuthenticationTokenFilter.java:41｜if 控制条件
  ```
  if (authHeader != null && authHeader.startsWith(this.tokenHead)) {
  ```
- call：mall-security/src/main/java/com/macro/mall/security/component/JwtAuthenticationTokenFilter.java:43｜调用 JwtTokenUtil.getUserNameFromToken/1
  ```
  String username = jwtTokenUtil.getUserNameFromToken(authToken);
  ```
- cfg_condition：mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:79｜try 异常控制路径
  ```
  try {
  ```
- call：mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:80｜调用 JwtTokenUtil.getPayloadFromToken/1
  ```
  Map<String, Object> payload = getPayloadFromToken(token);
  ```
- cfg_condition：mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:60｜try 异常控制路径
  ```
  try {
  ```
- cfg_condition：mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:62｜if 控制条件
  ```
  if (!JWTUtil.verify(token, getSigningKey())) {
  ```
- sink：mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:63｜日志输出 sink
  ```
  LOGGER.info("JWT签名验证失败:{}", token);
  ```

### 4. 跨方法外部输入未经规范化写入日志

- 风险类型：跨方法外部输入未经规范化写入日志
- 关联依赖漏洞：未明确
- 关联组件：未明确
- 风险位置：mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:69
- 代码范围：第 67-71 行
- 置信度：high
- 修复建议：升级日志组件到已确认的安全版本，并在写入日志前规范化换行符和表达式标记。
- CFG：source 到 sink 经过控制条件：mall-security/src/main/java/com/macro/mall/security/component/JwtAuthenticationTokenFilter.java:41；mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:79；mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:60；mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:68
- DFG：外部输入 API getHeader source → 调用 substring → 调用 JwtTokenUtil.getUserNameFromToken/1 → 调用 JwtTokenUtil.getPayloadFromToken/1 → 日志输出 sink
- 输入位置：mall-security/src/main/java/com/macro/mall/security/component/JwtAuthenticationTokenFilter.java:40

漏洞代码片段（第 67-71 行，风险点为第 69 行）：
```java
return JWTUtil.parseToken(token).getPayloads();
        } catch (Exception e) {
            LOGGER.info("JWT格式验证失败:{}", token);
            return null;
        }
```

修复后的代码：
```java
String safeLogValue = String.valueOf(token)
    .replace("\r", "\\r")
    .replace("\n", "\\n")
    .replace("${", "$ {");
LOGGER.info("JWT格式验证失败:{}", safeLogValue);
```

完整 Source→Sink 路径：
- source：mall-security/src/main/java/com/macro/mall/security/component/JwtAuthenticationTokenFilter.java:40｜外部输入 API getHeader source
  ```
  String authHeader = request.getHeader(this.tokenHeader);
  ```
- dataflow_step：mall-security/src/main/java/com/macro/mall/security/component/JwtAuthenticationTokenFilter.java:42｜调用 substring
  ```
  String authToken = authHeader.substring(this.tokenHead.length());// The part after "Bearer "
  ```
- cfg_condition：mall-security/src/main/java/com/macro/mall/security/component/JwtAuthenticationTokenFilter.java:41｜if 控制条件
  ```
  if (authHeader != null && authHeader.startsWith(this.tokenHead)) {
  ```
- call：mall-security/src/main/java/com/macro/mall/security/component/JwtAuthenticationTokenFilter.java:43｜调用 JwtTokenUtil.getUserNameFromToken/1
  ```
  String username = jwtTokenUtil.getUserNameFromToken(authToken);
  ```
- cfg_condition：mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:79｜try 异常控制路径
  ```
  try {
  ```
- call：mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:80｜调用 JwtTokenUtil.getPayloadFromToken/1
  ```
  Map<String, Object> payload = getPayloadFromToken(token);
  ```
- cfg_condition：mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:60｜try 异常控制路径
  ```
  try {
  ```
- cfg_condition：mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:68｜catch 异常控制路径
  ```
  } catch (Exception e) {
  ```
- sink：mall-security/src/main/java/com/macro/mall/security/util/JwtTokenUtil.java:69｜日志输出 sink
  ```
  LOGGER.info("JWT格式验证失败:{}", token);
  ```


## 5. 运行摘要

- 附件数量：16
- 依赖数量：19
- 依赖漏洞数量：0
- 代码漏洞数量：4
- 扫描策略：解析 pom.xml 与代码 import/require，按依赖包和版本匹配漏洞事实，并关联 source/sink 路径

## 6. 结论摘要

本次共识别 0 条依赖漏洞和 4 条代码漏洞。依赖漏洞应按组件版本范围完成升级或缓释；代码漏洞应按报告给出的文件、行号和修复代码逐项整改，并在修改后执行回归验证。另有 10 个依赖版本未明确，未计入漏洞命中；当前结果不能据此判定为安全。
