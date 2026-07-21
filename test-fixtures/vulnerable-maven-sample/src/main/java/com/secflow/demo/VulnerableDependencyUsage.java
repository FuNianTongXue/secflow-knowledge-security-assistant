package com.secflow.demo;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.util.Map;

/**
 * SecFlow 测试样例：
 * 这份代码只用于测试客户端依赖识别和报告生成。
 * 不包含 PoC、payload、攻击步骤或可直接利用的样例。
 */
public class VulnerableDependencyUsage {
    private static final Logger LOGGER = LogManager.getLogger(VulnerableDependencyUsage.class);
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Yaml yaml = new Yaml();

    public void logUserControlledMessage(String userControlledMessage) {
        // 测试点：代码 import 会辅助识别 log4j-core 依赖。
        // 真正风险判断应以后端根据 pom.xml 中的依赖版本查询到的漏洞事实为准。
        LOGGER.info("Received user message: {}", userControlledMessage);
    }

    public Map<?, ?> parseYamlConfig(String yamlText) {
        // 测试点：代码 import 会辅助识别 snakeyaml 依赖。
        // 生产环境应限制 YAML 输入来源，并升级到安全版本。
        Object parsed = yaml.load(yamlText);
        if (parsed instanceof Map<?, ?> map) {
            return map;
        }
        return Map.of();
    }

    public Object parseJson(String jsonText) throws IOException {
        // 测试点：代码 import 会辅助识别 jackson-databind 依赖。
        // 生产环境应避免对不可信 JSON 做宽泛 Object 反序列化。
        return objectMapper.readValue(jsonText, Object.class);
    }
}
