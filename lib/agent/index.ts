import { HTTPServerRequest, HTTPServerResponse } from "./cfnetwork";
import { parseNSData } from "./foundation";
import {
    IAgent,
    ICoverageEvent,
    ILogEvent,
    IRequestBodyEvent,
    IRequestDeallocatedEvent,
    IRequestHeadEvent,
    IResponseEvent,
    RequestId,
} from "./interfaces";

const { pointerSize } = Process;
const {
    NSAutoreleasePool,
    SDAirDropConnection,
} = ObjC.classes;

const TRUE = ptr(1);

const oslogFormatStringExpanders: { [name: string]: (format: string, cpuContext: any) => string } = {
    "x64": expandOslogFormatStringX64,
    "arm64": expandOslogFormatStringArm64,
};
const expandOslogFormatString = oslogFormatStringExpanders[Process.arch] || expandOslogFormatStringFallback;

class Agent implements IAgent {
    private startTime: number = Date.now();

    private requests: Map<string, RequestId> = new Map<string, RequestId>();
    private nextRequestId: number = 1;

    private requestDestructorListener: InvocationListener | null = null;

    private airdropLog: ObjC.Object | null = null;

    public async init(): Promise<void> {
        this.hookConnection();
        this.hookLogging();
    }

    public async dispose(): Promise<void> {
        if (this.airdropLog !== null) {
            this.airdropLog.release();
            this.airdropLog = null;
        }
    }

    private timeNow(): number {
        return Date.now() - this.startTime;
    }

    private hookConnection(): void {
        const self = this;

        Interceptor.attach(SDAirDropConnection["- didReceiveRequest:"].implementation, {
            onEnter(args) {
                const request = HTTPServerRequest.fromHandle(args[2]);

                const id = self.getRequestId(request);
                const { method, path, headers } = request;
                const event: IRequestHeadEvent = {
                    type: "request-head",
                    timestamp: self.timeNow(),
                    id,
                    method,
                    path,
                    headers,
                };
                send(event);
            }
        });

        Interceptor.attach(SDAirDropConnection["- processRequest"].implementation, {
            onEnter(args) {
                const connection = new ObjC.Object(args[0]);
                const ivars = connection.$ivars;

                let requestHandle: NativePointer = ivars._discoverRequest;
                if (requestHandle.isNull()) {
                    requestHandle = ivars._askRequest;
                }
                const request = HTTPServerRequest.fromHandle(requestHandle);

                const id = self.getRequestId(request);
                this.id = id;
                const timestamp = self.timeNow();
                this.timestamp = timestamp;
                const body: ObjC.Object | null = ivars._requestData;
                const event: IRequestBodyEvent = {
                    type: "request-body",
                    timestamp,
                    id,
                };
                send(event, parseNSData(body));

                const coverage: ArrayBuffer[] = [];
                this.coverage = coverage;
                Stalker.follow(this.threadId, {
                    events: {
                        compile: true
                    },
                    onReceive(rawEvents) {
                        coverage.push(rawEvents);
                    }
                });
            },
            onLeave() {
                Stalker.unfollow(this.threadId);
                Stalker.flush();

                const id: RequestId = this.id;
                const timestamp: number = this.timestamp;
                const coverage: ArrayBuffer[] = this.coverage;
                setTimeout(() => {
                    self.emitCoverageReport(id, coverage);
                }, 500);
            }
        });

        Interceptor.attach(SDAirDropConnection["- didSendResponse:forRequest:"].implementation, {
            onEnter(args) {
                const response = HTTPServerResponse.fromHandle(args[2]);
                const request = HTTPServerRequest.fromHandle(args[3]);

                const id = self.getRequestId(request);
                const { responseStatusLine, headers, body } = response.message;
                const event: IResponseEvent = {
                    type: "response",
                    timestamp: self.timeNow(),
                    id,
                    responseStatusLine,
                    headers,
                };
                send(event, parseNSData(body));
            }
        });
    }

    private getRequestId(request: HTTPServerRequest): RequestId {
        const { handle } = request;
        const key = handle.toString();

        let id = this.requests.get(key);
        if (id !== undefined) {
            return id;
        }

        id = this.nextRequestId++;
        this.requests.set(key, id);

        if (this.requestDestructorListener === null) {
            const vtable = handle.add(2 * pointerSize).readPointer();
            this.requestDestructorListener = Interceptor.attach(vtable.add(5 * pointerSize).readPointer(), args => {
                this.onRequestDestroyed(args[0]);
            });
        }

        return id;
    }

    private onRequestDestroyed(derivedHandle: NativePointer): void {
        const handle = derivedHandle.sub(2 * pointerSize);
        const key = handle.toString();

        const id = this.requests.get(key);
        if (id === undefined) {
            return;
        }
        this.requests.delete(key);

        const event: IRequestDeallocatedEvent = {
            type: "request-deallocated",
            timestamp: this.timeNow(),
            id: id,
        };
        send(event);
    }

    private emitCoverageReport(id: RequestId, coverage: ArrayBuffer[]): void {
        const allModules = new ModuleMap();
        const seenModules = new Set<string>();
        const modules: string[] = [];

        const symbols: string[] = [];

        coverage.forEach(rawEvents => {
            const events = Stalker.parse(rawEvents, { annotate: false }) as StalkerCompileEventBare[];
            events.forEach(ev => {
                const blockStart = ev[0] as NativePointer;

                const modulePath = allModules.findPath(blockStart);
                if (modulePath !== null && !seenModules.has(modulePath)) {
                    modules.push(modulePath);
                    seenModules.add(modulePath);
                }

                const symbol = DebugSymbol.fromAddress(blockStart);
                if (symbol.moduleName !== null) {
                    symbols.push(symbol.toString());
                }
            });
        });

        const event: ICoverageEvent = {
            type: "coverage",
            timestamp: this.timeNow(),
            id,
            modules,
            symbols,
        };
        send(event);
    }

    private hookLogging(): void {
        const self = this;

        const getAirdropLogHandle = new NativeFunction(Module.getExportByName(null, "airdrop_log"), "pointer", []) as any;

        const pool = NSAutoreleasePool.alloc().init();
        const airdropLog = new ObjC.Object(getAirdropLogHandle()).retain();
        this.airdropLog = airdropLog;
        pool.release();

        Interceptor.attach(Module.getExportByName(null, "os_log_type_enabled"), {
            onEnter(args) {
                this.log = args[0];
            },
            onLeave(retval) {
                if (this.log.equals(airdropLog)) {
                    retval.replace(TRUE);
                }
            }
        });

        Interceptor.attach(Module.getExportByName(null, "_os_log_impl"), {
            onEnter(args) {
                const log = args[1];
                if (log.equals(airdropLog)) {
                    const message = expandOslogFormatString(args[3].readUtf8String() as string, this.context);
                    const event: ILogEvent = {
                        type: "log",
                        timestamp: self.timeNow(),
                        message,
                    };
                    send(event);
                }
            }
        });
    }
}

function expandOslogFormatStringX64(format: string, context: X64CpuContext): string {
    let state: "good" | "bad" = "good";

    let { r8 } = context;
    r8 = r8.add(2);

    return format.replace(/(%\S)/g, (token: string, ...args: any[]) => {
        if (state === "bad") {
            return token;
        }

        r8 = r8.add(2);

        let value: string = token;
        let size = 0;

        switch (token) {
            case "%d": {
                value = r8.readS32().toString();
                size = 4;
                break;
            }
            case "%s": {
                const p = r8.readPointer();
                if (!p.isNull()) {
                    value = p.readUtf8String() as string;
                } else {
                    value = "(null)";
                }
                size = pointerSize;
                break;
            }
            case "%p": {
                const p = r8.readPointer();
                value = p.toString();
                size = pointerSize;
                break;
            }
            case "%@": {
                const p = r8.readPointer();
                if (!p.isNull()) {
                    const obj = new ObjC.Object(p);
                    value = obj.toString();
                } else {
                    value = "(nil)";
                }
                size = pointerSize;
                break;
            }
            case "%%":
                return token;
            default:
        }

        if (size !== 0) {
            r8 = r8.add(pointerSize);
        } else {
            state = "bad";
        }

        return value;
    });
}

function expandOslogFormatStringArm64(format: string, context: Arm64CpuContext): string {
    let state: "good" | "bad" = "good";

    let { sp } = context;
    sp = sp.add(2);

    return format.replace(/(%\S)/g, (token: string, ...args: any[]) => {
        if (state === "bad") {
            return token;
        }

        sp = sp.add(2);

        let value: string = token;
        let size = 0;

        switch (token) {
            case "%d": {
                value = sp.readS32().toString();
                size = 4;
                break;
            }
            case "%s": {
                const p = sp.readPointer();
                if (!p.isNull()) {
                    value = p.readUtf8String() as string;
                } else {
                    value = "(null)";
                }
                size = pointerSize;
                break;
            }
            case "%p": {
                const p = sp.readPointer();
                value = p.toString();
                size = pointerSize;
                break;
            }
            case "%@": {
                const p = sp.readPointer();
                if (!p.isNull()) {
                    const obj = new ObjC.Object(p);
                    value = obj.toString();
                } else {
                    value = "(nil)";
                }
                size = pointerSize;
                break;
            }
            case "%%":
                return token;
            default:
        }

        if (size !== 0) {
            sp = sp.add(pointerSize);
        } else {
            state = "bad";
        }

        return value;
    });
}

function expandOslogFormatStringFallback(format: string, context: PortableCpuContext): string {
    return format;
}

const agent = new Agent();
const exportedApi: IAgent = {
    init: Agent.prototype.init.bind(agent),
    dispose: Agent.prototype.dispose.bind(agent),
};
rpc.exports = exportedApi as any;
