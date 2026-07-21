# SecFlow Vulnerable Maven Sample

这是给 mac 客户端智能问答上传测试用的样例项目。

建议测试方式：

1. 在智能问答里点击添加文件。
2. 先上传 `pom.xml`，提问：`请根据附件依赖生成漏洞分析报告`。
3. 如需测试代码附件识别，再上传 `src/main/java/com/secflow/demo/VulnerableDependencyUsage.java`。

注意：

- 该样例只用于依赖漏洞识别测试。
- 代码文件不包含 PoC、payload、攻击步骤或可直接利用的样例。
- 当前 mac 客户端上传控件一次只选择一个文件；`pom.xml` 的命中准确性高于单独代码文件，因为它包含明确版本号。
