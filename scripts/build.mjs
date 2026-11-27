#!/usr/bin/env node
/**
 * Zero-dependency rule-set compiler for zhbcn/rule.
 *
 * Reads single-source YAML files in `src/*.yaml` and emits:
 *   - Mihomo / Stash:
 *       - dist/meta/domain/<name>.list + .mrs     (when domain or domain_suffix is non-empty)
 *       - dist/meta/ipcidr/<name>.list + .mrs     (when ip_cidr is non-empty)
 *       - dist/meta/classical/<name>.list         (when domain_keyword is non-empty)
 *   - Egern:
 *       - dist/egern/<name>.yaml                  (native Egern rule-set YAML)
 *
 * Usage:
 *   node scripts/build.mjs [--mihomo <path-to-mihomo>] [--skip-mrs]
 */

import { execFileSync } from "node:child_process";
import { mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { isIP } from "node:net";
import { basename, extname, join, resolve } from "node:path";

const ALLOWED_KEYS = new Set(["domain", "domain_suffix", "ip_cidr", "domain_keyword"]);
const NAME_RE = /^[a-z0-9][a-z0-9-]*$/;
const DOMAIN_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/;

function parseArgs(argv) {
  let mihomoBin = process.env.MIHOMO_BIN || "mihomo";
  let skipMrs = false;

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--mihomo") {
      const next = argv[i + 1];
      if (!next) throw new Error("--mihomo requires a binary path");
      mihomoBin = next;
      i += 1;
    } else if (arg === "--skip-mrs") {
      skipMrs = true;
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  return { mihomoBin, skipMrs };
}

function stripInlineComment(raw) {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < raw.length; i += 1) {
    const ch = raw[i];
    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
    } else if (ch === '"' && !inSingle && raw[i - 1] !== "\\") {
      inDouble = !inDouble;
    } else if (ch === "#" && !inSingle && !inDouble && (i === 0 || /\s/.test(raw[i - 1]))) {
      return raw.slice(0, i).trim();
    }
  }
  return raw.trim();
}

function unquoteScalar(value, filePath, lineNo) {
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    if (value.length < 2) {
      throw new Error(`${filePath}:${lineNo}: empty quoted value`);
    }
    return value.slice(1, -1).trim();
  }
  if (value.startsWith('"') || value.startsWith("'")) {
    throw new Error(`${filePath}:${lineNo}: unterminated quote in "${value}"`);
  }
  return value.trim();
}

function parseRuleSource(filePath) {
  const raw = readFileSync(filePath, "utf8");
  const lines = raw.split(/\r?\n/);
  const data = {
    domain: [],
    domain_suffix: [],
    ip_cidr: [],
    domain_keyword: [],
  };

  let currentKey = null;

  for (let i = 0; i < lines.length; i += 1) {
    const lineNo = i + 1;
    const cleaned = stripInlineComment(lines[i]);
    if (!cleaned) continue;

    // Top-level section key (must not be indented)
    if (!/^\s/.test(lines[i]) && cleaned.includes(":")) {
      const colonIdx = cleaned.indexOf(":");
      const key = cleaned.slice(0, colonIdx).trim();
      const rest = cleaned.slice(colonIdx + 1).trim();

      if (!ALLOWED_KEYS.has(key)) {
        throw new Error(
          `${filePath}:${lineNo}: unsupported key "${key}" (allowed: ${[...ALLOWED_KEYS].join(", ")})`,
        );
      }
      if (rest === "" || rest === "[]") {
        currentKey = rest === "[]" ? null : key;
        continue;
      }
      throw new Error(
        `${filePath}:${lineNo}: key "${key}" must be followed by a YAML list (or [])`,
      );
    }

    // List item under currentKey
    if (cleaned.startsWith("- ")) {
      if (!currentKey) {
        throw new Error(`${filePath}:${lineNo}: list item appears before any section key`);
      }
      const value = unquoteScalar(cleaned.slice(2).trim(), filePath, lineNo);
      if (!value) {
        throw new Error(`${filePath}:${lineNo}: empty rule value`);
      }
      data[currentKey].push({ value, lineNo });
      continue;
    }

    throw new Error(`${filePath}:${lineNo}: invalid syntax "${cleaned}"`);
  }

  return normalizeAndValidate(filePath, data);
}

function validateDomain(value, key, filePath, lineNo) {
  const lower = value.toLowerCase();
  if (lower.startsWith("+.") || lower.startsWith(".")) {
    throw new Error(
      `${filePath}:${lineNo}: ${key} entry "${value}" must not start with "." or "+."`,
    );
  }
  if (!DOMAIN_RE.test(lower)) {
    throw new Error(`${filePath}:${lineNo}: invalid ${key} value "${value}"`);
  }
  return lower;
}

function validateCidr(value, filePath, lineNo) {
  const parts = value.split("/");
  if (parts.length !== 2) {
    throw new Error(`${filePath}:${lineNo}: ip_cidr "${value}" must be in <ip>/<prefix> format`);
  }
  const [ip, prefixRaw] = parts;
  const version = isIP(ip);
  if (version !== 4 && version !== 6) {
    throw new Error(`${filePath}:${lineNo}: invalid IP address in ip_cidr "${value}"`);
  }
  if (!/^\d+$/.test(prefixRaw)) {
    throw new Error(`${filePath}:${lineNo}: invalid prefix length in ip_cidr "${value}"`);
  }
  const prefix = Number(prefixRaw);
  const maxPrefix = version === 4 ? 32 : 128;
  if (prefix < 0 || prefix > maxPrefix) {
    throw new Error(
      `${filePath}:${lineNo}: prefix length ${prefix} out of range (0..${maxPrefix}) in "${value}"`,
    );
  }
  return { cidr: `${ip.toLowerCase()}/${prefix}`, version };
}

function validateKeyword(value, filePath, lineNo) {
  const lower = value.toLowerCase();
  if (/[\s,]/.test(lower)) {
    throw new Error(
      `${filePath}:${lineNo}: domain_keyword "${value}" must not contain whitespace or commas`,
    );
  }
  return lower;
}

function dedupeSort(items) {
  return [...new Set(items)].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

function normalizeAndValidate(filePath, raw) {
  const domain = dedupeSort(
    raw.domain.map(({ value, lineNo }) => validateDomain(value, "domain", filePath, lineNo)),
  );
  const domainSuffix = dedupeSort(
    raw.domain_suffix.map(({ value, lineNo }) =>
      validateDomain(value, "domain_suffix", filePath, lineNo),
    ),
  );
  const ipv4 = [];
  const ipv6 = [];
  for (const { value, lineNo } of raw.ip_cidr) {
    const parsed = validateCidr(value, filePath, lineNo);
    if (parsed.version === 4) ipv4.push(parsed.cidr);
    else ipv6.push(parsed.cidr);
  }
  const ipCidr4 = dedupeSort(ipv4);
  const ipCidr6 = dedupeSort(ipv6);
  const domainKeyword = dedupeSort(
    raw.domain_keyword.map(({ value, lineNo }) => validateKeyword(value, filePath, lineNo)),
  );

  const total =
    domain.length + domainSuffix.length + ipCidr4.length + ipCidr6.length + domainKeyword.length;
  if (total === 0) {
    throw new Error(`${filePath}: rule-set has no rules`);
  }

  return {
    domain,
    domainSuffix,
    ipCidr4,
    ipCidr6,
    domainKeyword,
  };
}

function formatYamlScalar(value) {
  if (/^[a-z0-9._:/-]+$/i.test(value) && !/^(true|false|null|~)$/i.test(value)) {
    return value;
  }
  return JSON.stringify(value);
}

function renderEgernYaml(ruleSet) {
  const lines = [];
  const hasIp = ruleSet.ipCidr4.length > 0 || ruleSet.ipCidr6.length > 0;
  if (hasIp) {
    lines.push("no_resolve: true");
  }
  if (ruleSet.domain.length > 0) {
    lines.push("domain_set:");
    for (const item of ruleSet.domain) {
      lines.push(`- ${formatYamlScalar(item)}`);
    }
  }
  if (ruleSet.domainSuffix.length > 0) {
    lines.push("domain_suffix_set:");
    for (const item of ruleSet.domainSuffix) {
      lines.push(`- ${formatYamlScalar(item)}`);
    }
  }
  if (ruleSet.domainKeyword.length > 0) {
    lines.push("domain_keyword_set:");
    for (const item of ruleSet.domainKeyword) {
      lines.push(`- ${formatYamlScalar(item)}`);
    }
  }
  if (ruleSet.ipCidr4.length > 0) {
    lines.push("ip_cidr_set:");
    for (const item of ruleSet.ipCidr4) {
      lines.push(`- ${formatYamlScalar(item)}`);
    }
  }
  if (ruleSet.ipCidr6.length > 0) {
    lines.push("ip_cidr6_set:");
    for (const item of ruleSet.ipCidr6) {
      lines.push(`- ${formatYamlScalar(item)}`);
    }
  }
  return `${lines.join("\n")}\n`;
}

function convertToMrs(mihomoBin, behavior, listPath, mrsPath) {
  execFileSync(mihomoBin, ["convert-ruleset", behavior, "text", listPath, mrsPath], {
    stdio: "inherit",
    windowsHide: true,
  });
  const stat = statSync(mrsPath);
  if (stat.size === 0) {
    throw new Error(`Generated .mrs file is empty: ${mrsPath}`);
  }
}

function main() {
  const { mihomoBin, skipMrs } = parseArgs(process.argv.slice(2));
  const rootDir = resolve(import.meta.dirname, "..");
  const srcDir = join(rootDir, "src");
  const distDir = join(rootDir, "dist");

  const entries = readdirSync(srcDir)
    .filter((file) => extname(file) === ".yaml")
    .sort();

  if (entries.length === 0) {
    throw new Error(`No .yaml rule files found in ${srcDir}`);
  }

  rmSync(distDir, { recursive: true, force: true });
  mkdirSync(join(distDir, "egern"), { recursive: true });

  const summary = [];

  for (const file of entries) {
    const name = basename(file, ".yaml");
    if (!NAME_RE.test(name)) {
      throw new Error(`Invalid rule file name "${file}" (must match ${NAME_RE})`);
    }
    const parsed = parseRuleSource(join(srcDir, file));
    const outputs = [];

    // 1. Egern YAML (all rule types in one native YAML file)
    const egernOut = join(distDir, "egern", `${name}.yaml`);
    writeFileSync(egernOut, renderEgernYaml(parsed), "utf8");
    outputs.push(`egern/${name}.yaml`);

    // 2. Mihomo / Stash: domain (.list + .mrs)
    if (parsed.domain.length > 0 || parsed.domainSuffix.length > 0) {
      const domainDir = join(distDir, "meta", "domain");
      mkdirSync(domainDir, { recursive: true });
      const domainLines = [
        ...parsed.domain,
        ...parsed.domainSuffix.map((suffix) => `+.${suffix}`),
      ];
      const listPath = join(domainDir, `${name}.list`);
      const mrsPath = join(domainDir, `${name}.mrs`);
      writeFileSync(listPath, `${domainLines.join("\n")}\n`, "utf8");
      outputs.push(`meta/domain/${name}.list`);
      if (!skipMrs) {
        convertToMrs(mihomoBin, "domain", listPath, mrsPath);
        outputs.push(`meta/domain/${name}.mrs`);
      }
    }

    // 3. Mihomo / Stash: ipcidr (.list + .mrs)
    if (parsed.ipCidr4.length > 0 || parsed.ipCidr6.length > 0) {
      const ipcidrDir = join(distDir, "meta", "ipcidr");
      mkdirSync(ipcidrDir, { recursive: true });
      const ipLines = [...parsed.ipCidr4, ...parsed.ipCidr6];
      const listPath = join(ipcidrDir, `${name}.list`);
      const mrsPath = join(ipcidrDir, `${name}.mrs`);
      writeFileSync(listPath, `${ipLines.join("\n")}\n`, "utf8");
      outputs.push(`meta/ipcidr/${name}.list`);
      if (!skipMrs) {
        convertToMrs(mihomoBin, "ipcidr", listPath, mrsPath);
        outputs.push(`meta/ipcidr/${name}.mrs`);
      }
    }

    // 4. Mihomo / Stash: classical (.list only; .mrs does not support classical)
    if (parsed.domainKeyword.length > 0) {
      const classicalDir = join(distDir, "meta", "classical");
      mkdirSync(classicalDir, { recursive: true });
      const classicalLines = parsed.domainKeyword.map((kw) => `DOMAIN-KEYWORD,${kw}`);
      const listPath = join(classicalDir, `${name}.list`);
      writeFileSync(listPath, `${classicalLines.join("\n")}\n`, "utf8");
      outputs.push(`meta/classical/${name}.list`);
    }

    summary.push({
      name,
      counts: {
        domain: parsed.domain.length,
        domain_suffix: parsed.domainSuffix.length,
        ip_cidr: parsed.ipCidr4.length + parsed.ipCidr6.length,
        domain_keyword: parsed.domainKeyword.length,
      },
      outputs,
    });
  }

  console.log("[build] Compiled rule-sets:");
  for (const item of summary) {
    const c = item.counts;
    console.log(
      `  - ${item.name}: domain=${c.domain}, suffix=${c.domain_suffix}, ipcidr=${c.ip_cidr}, keyword=${c.domain_keyword} -> ${item.outputs.join(", ")}`,
    );
  }
}

main();
