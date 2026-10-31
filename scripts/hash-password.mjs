// Prints a bcrypt hash of a password read from stdin, so the password stays out
// of shell history. Prompts without echoing when stdin is a terminal.
import { createInterface } from "node:readline/promises";
import { Writable } from "node:stream";
import bcrypt from "bcryptjs";

const silent = new Writable({ write: (_chunk, _encoding, done) => done() });
const reader = createInterface({
  input: process.stdin,
  output: silent,
  terminal: Boolean(process.stdin.isTTY),
});

if (process.stdin.isTTY) process.stderr.write("Password: ");
const { value: password } = await reader[Symbol.asyncIterator]().next();
reader.close();
if (process.stdin.isTTY) process.stderr.write("\n");

if (!password) {
  console.error("No password given");
  process.exit(1);
}
process.stdout.write(await bcrypt.hash(password, 10));
