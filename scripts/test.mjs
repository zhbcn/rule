import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const rootDir = resolve(import.meta.dirname, "..");
const buildScript = join(rootDir, "scripts", "build.mjs");

function runBuild(cwd, extraArgs = []) {
  return execFileSync(process.execPath, [join(cwd, "scripts", "build.mjs"), ...extraArgs], {
    cwd,
    encoding: "utf8",
    stdio: "pipe",
  });
}

function createTempRepo() {
  const dir = mkdtempSync(join(tmpdir(), "zhbcn-rule-test-"));
  cpSync(join(rootDir, "scripts"), join(dir, "scripts"), { recursive: true });
  cpSync(join(rootDir, "src"), join(dir, "src"), { recursive: true });
  return dir;
}

test("仓库现有 src/*.yaml 全部通过语法校验并正确产出 Egern YAML 与 Mihomo list", () => {
  const dir = createTempRepo();
  try {
    const mihomoBin = process.env.MIHOMO_BIN;
    const args = mihomoBin && existsSync(mihomoBin) ? ["--mihomo", mihomoBin] : ["--skip-mrs"];
    runBuild(dir, args);

    const financeEgern = readFileSync(join(dir, "dist/egern/custom-finance.yaml"), "utf8");
    const financeList = readFileSync(join(dir, "dist/meta/domain/custom-finance.list"), "utf8");
    assert.ok(financeEgern.includes("- wise.com"));
    assert.ok(financeEgern.includes("- stripe.com"));
    assert.ok(financeList.includes("+.wise.com"));
    assert.ok(!financeEgern.includes("no_resolve:"), "纯域名规则集不应输出 no_resolve");

    const publicEgern = readFileSync(join(dir, "dist/egern/custom-public.yaml"), "utf8");
    const publicList = readFileSync(join(dir, "dist/meta/domain/custom-public.list"), "utf8");
    assert.ok(publicEgern.includes("- 1password.com"));
    assert.ok(publicEgern.includes("- bitwarden.com"));
    assert.ok(publicEgern.includes("- proton.me"));
    assert.ok(publicList.includes("+.proton.me"));

    // 未使用的分类不得产出空文件
    assert.equal(existsSync(join(dir, "dist/meta/ipcidr/custom-finance.list")), false);
    assert.equal(existsSync(join(dir, "dist/meta/classical/custom-finance.list")), false);
    assert.equal(existsSync(join(dir, "dist/meta/ipcidr/custom-public.list")), false);
    assert.equal(existsSync(join(dir, "dist/meta/classical/custom-public.list")), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("支持 domain / domain_suffix / ip_cidr (IPv4+IPv6) / domain_keyword 并去重排序", () => {
  const dir = createTempRepo();
  try {
    writeFileSync(
      join(dir, "src/custom-mixed.yaml"),
      [
        "domain:",
        "  - Exact.Example.Invalid",
        "  - exact.example.invalid # duplicate",
        "domain_suffix:",
        "  - b.example.invalid",
        "  - a.example.invalid",
        "ip_cidr:",
        "  - 203.0.113.0/24",
        "  - 2001:DB8::/32",
        "domain_keyword:",
        "  - SampleKW",
        "",
      ].join("\n"),
      "utf8",
    );

    runBuild(dir, ["--skip-mrs"]);

    const egern = readFileSync(join(dir, "dist/egern/custom-mixed.yaml"), "utf8");
    assert.equal(
      egern,
      [
        "no_resolve: true",
        "domain_set:",
        "- exact.example.invalid",
        "domain_suffix_set:",
        "- a.example.invalid",
        "- b.example.invalid",
        "domain_keyword_set:",
        "- samplekw",
        "ip_cidr_set:",
        "- 203.0.113.0/24",
        "ip_cidr6_set:",
        "- 2001:db8::/32",
        "",
      ].join("\n"),
    );

    const domainList = readFileSync(join(dir, "dist/meta/domain/custom-mixed.list"), "utf8");
    assert.equal(
      domainList,
      ["exact.example.invalid", "+.a.example.invalid", "+.b.example.invalid", ""].join("\n"),
    );

    const ipList = readFileSync(join(dir, "dist/meta/ipcidr/custom-mixed.list"), "utf8");
    assert.equal(ipList, ["203.0.113.0/24", "2001:db8::/32", ""].join("\n"));

    const classicalList = readFileSync(join(dir, "dist/meta/classical/custom-mixed.list"), "utf8");
    assert.equal(classicalList, "DOMAIN-KEYWORD,samplekw\n");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("严格拦截非法前缀点、非法 CIDR、未知字段与空规则集", () => {
  const cases = [
    { name: "bad-dot", content: "domain_suffix:\n  - .example.invalid\n", pattern: /must not start/ },
    { name: "bad-plus", content: "domain_suffix:\n  - +.example.invalid\n", pattern: /must not start/ },
    { name: "bad-cidr", content: "ip_cidr:\n  - 203.0.113.0/33\n", pattern: /out of range/ },
    { name: "bad-key", content: "process_name:\n  - app.exe\n", pattern: /unsupported key/ },
    { name: "empty", content: "domain: []\n", pattern: /has no rules/ },
  ];

  for (const tc of cases) {
    const dir = createTempRepo();
    try {
      writeFileSync(join(dir, "src", `${tc.name}.yaml`), tc.content, "utf8");
      assert.throws(
        () => runBuild(dir, ["--skip-mrs"]),
        (err) => {
          const stderr = String(err.stderr ?? err.message ?? "");
          assert.match(stderr, tc.pattern, `Case ${tc.name} stderr: ${stderr}`);
          return true;
        },
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

test("buildScript 路径存在且可直接执行", () => {
  assert.equal(existsSync(buildScript), true);
});
