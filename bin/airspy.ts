import {
    AgentEvent,
    Application,
    IConfig,
    IDelegate,
    IOperation,
    IRequestBodyEvent,
    IRequestCoverageEvent,
    IRequestDeallocatedEvent,
    IRequestHeadEvent,
    IResponseEvent,
    LogLevel,
    TargetDevice,
} from "../lib";

import * as bplist from "bplist-parser";
import chalk, { Chalk } from "chalk";
import * as program from "commander";
import * as fs from "fs";
import * as fsPath from "path";
import * as plist from "plist";
import * as prettyHrtime from "pretty-hrtime";
import { Writable } from "stream";
import { promisify } from "util";

const access = promisify(fs.access);
const mkdir = promisify(fs.mkdir);

const inboundPrefix = chalk.gray("<<<  ");
const outboundPrefix = chalk.gray(">>>  ");

async function main(): Promise<void> {
    try {
        const config = parseArguments();
        const ui = new ConsoleUI();

        let app: Application | null = new Application(config, ui);

        process.on("SIGINT", stop);
        process.on("SIGTERM", stop);

        await app.run();

        function stop(): void {
            if (app !== null) {
                app.dispose();
                app = null;
            }
        }
    } catch (error) {
        process.exitCode = 1;
        process.stderr.write(`${chalk.redBright(error.message)}\n`);
    }
}

function parseArguments(): IConfig {
    let targetDevice: TargetDevice = {
        kind: "local"
    };

    program
        .option("-U, --usb", "Connect to USB device", () => {
            targetDevice = {
                kind: "usb"
            };
        })
        .option("-R, --remote", "Connect to remote frida-server", () => {
            targetDevice = {
                kind: "remote"
            };
        })
        .option("-D, --device [ID]", "Connect to device with the given ID", (id: string) => {
            targetDevice = {
                kind: "by-id",
                id: id
            };
        })
        .parse(process.argv);

    return {
        targetDevice,
    };
}

class ConsoleUI implements IDelegate {
    private pendingOperation: IPendingOperation | null = null;

    private getOutputDirPromise: Promise<string> | null = null;
    private getEventOutputStreamPromise: Promise<Writable> | null = null;

    public onProgress(operation: IOperation): void {
        process.stdout.write(`[${operation.scope}] ${chalk.cyan(operation.description)} `);

        const pending = {
            operation: operation,
            logMessageCount: 0,
        };
        this.pendingOperation = pending;

        operation.onceComplete(() => {
            if (pending.logMessageCount > 0) {
                process.stdout.write(`[${operation.scope}] ${chalk.cyan(`${operation.description} completed`)} `);
            }

            process.stdout.write(chalk.gray(`(${prettyHrtime(operation.elapsed)})\n`));

            this.pendingOperation = null;
        });
    }

    public onConsoleMessage(scope: string, level: LogLevel, text: string): void {
        let c: Chalk;
        switch (level) {
            case "info":
                c = chalk.whiteBright;
                break;
            case "warning":
                c = chalk.yellowBright;
                break;
            case "error":
                c = chalk.redBright;
                break;
            default:
                c = chalk.grey;
        }

        const pending = this.pendingOperation;
        if (pending !== null) {
            if (pending.logMessageCount === 0) {
                process.stdout.write(`${chalk.gray("...")}\n`);
            }

            pending.logMessageCount += 1;
        }

        process.stdout.write(`[${scope}] ${c(text)}\n`);
    }

    public onEvent(event: AgentEvent, data: Buffer | null): void {
        this.logEvent(event, data);

        switch (event.type) {
            case "request-head":
                this.onRequestHead(event);
                break;
            case "request-body":
                this.onRequestBody(event, data as Buffer);
                break;
            case "request-coverage":
                this.onRequestCoverage(event);
                break;
            case "request-deallocated":
                this.onRequestDeallocated(event);
                break;
            case "response":
                this.onResponse(event, data);
                break;
            default:
                console.error("Unhandled event:", event);
        }
    }

    private onRequestHead(event: IRequestHeadEvent): void {
        const { id, method, path, headers } = event;

        this.printLines(inboundPrefix,
            [
                chalk.cyan(`[ID: ${id}] ${method} ${path}`),
            ]
            .concat(headers.map(({ name, value }) => `${chalk.green(name)}: ${value}`))
        );
    }

    private onRequestBody(event: IRequestBodyEvent, data: Buffer): void {
        this.printLines(inboundPrefix,
            [
                chalk.cyan(`[ID: ${event.id}]`),
            ]
            .concat(hexdump(data, { header: false, ansi: true }).split("\n"))
            .concat([ "=>" ])
            .concat(this.parseBody(data).split("\n"))
        );
    }

    private onRequestCoverage(event: IRequestCoverageEvent): void {
    }

    private onRequestDeallocated(event: IRequestDeallocatedEvent): void {
    }

    private onResponse(event: IResponseEvent, data: Buffer | null): void {
        const { id, responseStatusLine, headers } = event;

        let lines = [
                chalk.cyan(`[ID: ${id}] ${responseStatusLine}`),
            ]
            .concat(headers.map(({ name, value }) => `${chalk.green(name)}: ${value}`));
        if (data !== null) {
            lines = lines.concat(hexdump(data, { header: false, ansi: true }).split("\n"))
                .concat([ "=>" ])
                .concat(this.parseBody(data).split("\n"));
        }

        this.printLines(outboundPrefix, lines);
    }

    private parseBody(body: Buffer): string {
        const [ root ] = bplist.parseBuffer(body);

        return plist.build(root);
    }

    private printLines(prefix: string, lines: string[]): void {
        const message = [""].concat(lines).join(`\n${prefix}`);
        process.stdout.write(`${message}\n`);
    }

    private async logEvent(event: AgentEvent, data: Buffer | null): Promise<void> {
        try {
            const output = await this.getEventOutputStream();
            const line = JSON.stringify([
                event,
                (data !== null) ? data.toString("base64") : null
            ]);
            output.write(`${line}\n`, "utf-8");
        } catch (e) {
            console.error(e);
        }
    }

    private getOutputDir(): Promise<string> {
        if (this.getOutputDirPromise === null) {
            this.getOutputDirPromise = (async (): Promise<string> => {
                const rootDir = fsPath.resolve(__dirname, "..", "..", "out");

                let outDir: string;
                let exists: boolean;
                let serial = 0;
                do {
                    outDir = fsPath.join(rootDir, serial.toString());
                    try {
                        await access(outDir);
                        exists = true;
                        serial++;
                    } catch (e) {
                        exists = false;
                    }
                } while (exists);

                await mkdir(outDir, { recursive: true });

                return outDir;
            })();
        }

        return this.getOutputDirPromise;
    }

    private async getOutputPath(fileName: string): Promise<string> {
        const outputDir = await this.getOutputDir();
        const outputPath = fsPath.join(outputDir, fileName);

        await mkdir(fsPath.dirname(outputPath), { recursive: true });

        return outputPath;
    }

    private getEventOutputStream(): Promise<Writable> {
        if (this.getEventOutputStreamPromise === null) {
            this.getEventOutputStreamPromise = (async () => {
                const logPath = await this.getOutputPath("events.log");

                // tslint:disable-next-line:non-literal-fs-path
                return fs.createWriteStream(logPath, "utf8");
            })();
        }

        return this.getEventOutputStreamPromise;
    }
}

interface IPendingOperation {
    operation: IOperation;
    logMessageCount: number;
}

function hexdump(buffer: Buffer, options: IHexdumpOptions = {}): string {
    const {
        offset: startOffset = 0,
        length = buffer.length,
        header: showHeader = true,
        ansi: useAnsi = false,
    } = options;

    const columnPadding = "  ";
    const leftColumnWidth = 8;
    const hexLegend = " 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F";
    const asciiLegend = "0123456789ABCDEF";

    let resetColor: string;
    let offsetColor: string;
    let dataColor: string;
    let newlineColor: string;
    if (useAnsi) {
        resetColor = "\x1b[0m";
        offsetColor = "\x1b[0;32m";
        dataColor = "\x1b[0;33m";
        newlineColor = resetColor;
    } else {
        resetColor = "";
        offsetColor = "";
        dataColor = "";
        newlineColor = "";
    }

    const result = [];

    if (showHeader) {
        result.push(
            "        ",
            columnPadding,
            hexLegend,
            columnPadding,
            asciiLegend,
            "\n"
        );
    }

    let offset = startOffset;
    for (let bufferOffset = 0; bufferOffset < length; bufferOffset += 16) {
        if (bufferOffset !== 0) {
            result.push("\n");
        }

        result.push(
            offsetColor, offset.toString(16).padStart(leftColumnWidth, "0"), resetColor,
            columnPadding
        );

        const asciiChars = [];
        const lineSize = Math.min(length - offset, 16);

        for (let lineOffset = 0; lineOffset !== lineSize; lineOffset++) {
            const value = buffer[offset++];

            const isNewline = value === 10;

            const hexPair = value.toString(16).padStart(2, "0");
            if (lineOffset !== 0) {
                result.push(" ");
            }
            result.push(
                isNewline ? newlineColor : dataColor,
                hexPair,
                resetColor
            );

            asciiChars.push(
                isNewline ? newlineColor : dataColor,
                (value >= 32 && value <= 126) ? String.fromCharCode(value) : ".",
                resetColor
            );
        }

        for (let lineOffset = lineSize; lineOffset !== 16; lineOffset++) {
            result.push("   ");
            asciiChars.push(" ");
        }

        result.push(columnPadding);

        Array.prototype.push.apply(result, asciiChars);
    }

    let trailingSpaceCount = 0;
    for (let tailOffset = result.length - 1; tailOffset >= 0 && result[tailOffset] === " "; tailOffset--) {
        trailingSpaceCount++;
    }

    return result.slice(0, result.length - trailingSpaceCount).join("");
}

interface IHexdumpOptions {
    offset?: number;
    length?: number;
    header?: boolean;
    ansi?: boolean;
}

main();
