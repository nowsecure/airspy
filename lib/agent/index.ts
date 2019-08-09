import { HTTPServerRequest, HTTPServerResponse } from "./cfnetwork";
import { parseNSData } from "./foundation";
import {
    IAgent,
    IRequestBodyEvent,
    IRequestCoverageEvent,
    IRequestDeallocatedEvent,
    IRequestHeadEvent,
    IResponseEvent,
    RequestId,
} from "./interfaces";

const { pointerSize } = Process;
const {
    SDAirDropConnection,
} = ObjC.classes;

class Agent implements IAgent {
    private requests: Map<string, RequestId> = new Map<string, RequestId>();
    private nextRequestId: number = 1;

    private requestDestructorListener: InvocationListener | null = null;

    public async init(): Promise<void> {
        this.hookConnection();
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
                const body: ObjC.Object | null = ivars._requestData;
                const event: IRequestBodyEvent = {
                    type: "request-body",
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

        const event: IRequestCoverageEvent = {
            type: "request-coverage",
            id,
            modules,
            symbols,
        };
        send(event);
    }
}

const agent = new Agent();
const exportedApi: IAgent = {
    init: Agent.prototype.init.bind(agent),
};
rpc.exports = exportedApi as any;