import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import process from "node:process";
import solc from "solc";

const EXPECTED_VERSION = "0.8.35";
if (!solc.version().startsWith(`${EXPECTED_VERSION}+`)) {
  throw new Error(`expected solc ${EXPECTED_VERSION}, got ${solc.version()}`);
}

const source = await readFile(new URL("src/NativeEthHtlc.sol", import.meta.url), "utf8");
const input = {
  language: "Solidity",
  sources: { "NativeEthHtlc.sol": { content: source } },
  settings: {
    optimizer: { enabled: true, runs: 200 },
    evmVersion: "prague",
    metadata: { appendCBOR: false, bytecodeHash: "none" },
    outputSelection: {
      "*": { "*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"] }
    }
  }
};
const output = JSON.parse(solc.compile(JSON.stringify(input)));
const errors = (output.errors ?? []).filter((entry) => entry.severity === "error");
if (errors.length > 0) throw new Error(errors.map((entry) => entry.formattedMessage).join("\n"));

const contract = output.contracts["NativeEthHtlc.sol"].NativeEthHtlc;
const runtime = Buffer.from(contract.evm.deployedBytecode.object, "hex");
const artifact = {
  compiler: solc.version(),
  settings: input.settings,
  sourceSha256: createHash("sha256").update(source).digest("hex"),
  runtimeLength: runtime.length,
  abi: contract.abi,
  bytecode: `0x${contract.evm.bytecode.object}`,
  deployedBytecode: `0x${contract.evm.deployedBytecode.object}`
};
const encoded = `${JSON.stringify(artifact, null, 2)}\n`;
const artifactUrl = new URL("artifacts/NativeEthHtlc.json", import.meta.url);

if (process.argv.includes("--check")) {
  const existing = await readFile(artifactUrl, "utf8");
  if (existing !== encoded) throw new Error("contract artifact is stale");
} else {
  await mkdir(new URL("artifacts/", import.meta.url), { recursive: true });
  await writeFile(artifactUrl, encoded);
}
