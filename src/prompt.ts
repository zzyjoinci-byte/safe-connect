import { createInterface } from "node:readline";
import { stdin as processInput, stdout as processOutput } from "node:process";

export interface PromptInput {
  isTTY?: boolean;
  isRaw?: boolean;
  setRawMode?(mode: boolean): this | void;
  on(event: "data", listener: (chunk: Buffer) => void): this | void;
  off(event: "data", listener: (chunk: Buffer) => void): this | void;
  pause(): this | void;
  resume(): this | void;
}

export interface PromptOutput {
  write(chunk: string): unknown;
}

const defaultIO = () => ({ input: processInput as PromptInput, output: processOutput as PromptOutput });

export async function promptLine(question: string): Promise<string> {
  const rl = createInterface({ input: processInput, output: processOutput });
  const answer = await new Promise<string>((resolve) => {
    rl.question(question, resolve);
  });
  rl.close();
  return answer.trim();
}

/**
 * Read a hidden line from a stream. Pasted TTY input arrives as one chunk and
 * may include bracketed-paste markers plus a trailing newline from the previous
 * prompt; walk character-by-character and ignore empty newlines.
 */
export async function promptHidden(
  question: string,
  io: { input: PromptInput; output: PromptOutput } = defaultIO(),
): Promise<string> {
  const { input, output } = io;
  return new Promise((resolve, reject) => {
    output.write(question);
    const wasRaw = input.isRaw;
    if (input.isTTY) input.setRawMode?.(true);
    let value = "";
    const onData = (chunk: Buffer) => {
      // Pasted text arrives as one chunk (possibly wrapped in bracketed-paste markers),
      // so walk it character by character instead of comparing the whole chunk.
      const s = chunk.toString("utf8").replace(/\u001b\[20[01]~/g, "");
      for (const ch of s) {
        if (ch === "\u0003") {
          cleanup();
          output.write("\n");
          reject(new Error("interrupted"));
          return;
        }
        if (ch === "\n" || ch === "\r") {
          if (value.length === 0) continue; // ignore stray newline left over from the previous prompt
          cleanup();
          output.write("\n");
          resolve(value);
          return;
        }
        if (ch === "\u007f" || ch === "\b") {
          value = value.slice(0, -1);
          continue;
        }
        if (ch >= " ") value += ch;
      }
    };
    const cleanup = () => {
      input.off("data", onData);
      if (input.isTTY) input.setRawMode?.(wasRaw ?? false);
      input.pause();
    };
    input.on("data", onData);
    input.resume();
  });
}

export async function promptSecret(
  label: string,
  fromEnv?: string,
  io: { input: PromptInput; output: PromptOutput } = defaultIO(),
): Promise<string> {
  if (fromEnv && fromEnv.length > 0) return fromEnv;
  if (!io.input.isTTY) {
    throw new Error(`${label} required (set env or pass -- flag; stdin is not a TTY)`);
  }
  for (let i = 0; i < 3; i++) {
    const v = await promptHidden(`${label}: `, io);
    if (v.length > 0) return v;
    io.output.write(`${label} cannot be empty.\n`);
  }
  throw new Error(`${label} is empty`);
}
