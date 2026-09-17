import { createInterface } from "node:readline";
import { stdin as input, stdout as output } from "node:process";

export async function promptLine(question: string): Promise<string> {
  const rl = createInterface({ input, output });
  const answer = await new Promise<string>((resolve) => {
    rl.question(question, resolve);
  });
  rl.close();
  return answer.trim();
}

export async function promptHidden(question: string): Promise<string> {
  return new Promise((resolve, reject) => {
    output.write(question);
    const wasRaw = input.isRaw;
    if (input.isTTY) input.setRawMode(true);
    let value = "";
    const onData = (chunk: Buffer) => {
      const s = chunk.toString("utf8");
      if (s === "\u0003") {
        cleanup();
        output.write("\n");
        reject(new Error("interrupted"));
        return;
      }
      if (s === "\n" || s === "\r") {
        cleanup();
        output.write("\n");
        resolve(value);
        return;
      }
      if (s === "\u007f" || s === "\b") {
        value = value.slice(0, -1);
        return;
      }
      if (s >= " ") value += s;
    };
    const cleanup = () => {
      input.off("data", onData);
      if (input.isTTY) input.setRawMode(wasRaw ?? false);
    };
    input.on("data", onData);
  });
}

export async function promptSecret(label: string, fromEnv?: string): Promise<string> {
  if (fromEnv && fromEnv.length > 0) return fromEnv;
  if (!input.isTTY) {
    throw new Error(`${label} required (set env or pass -- flag; stdin is not a TTY)`);
  }
  return promptHidden(`${label}: `);
}
