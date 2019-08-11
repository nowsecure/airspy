import { IConfig, TargetDevice } from "./config";
import { IOperation, Operation } from "./operation";

import {
    AgentEvent,
    IAgent,
} from "./agent/interfaces";

import { EventEmitter } from "events";
import * as frida from "frida";
import * as fs from "fs";
import { promisify } from "util";

const readFile = promisify(fs.readFile);

export class Application {
    private config: IConfig;
    private delegate: IDelegate;

    private device: frida.Device | null = null;
    private process: frida.Process | null = null;
    private agents: Map<number, Agent> = new Map<number, Agent>();
    private done: Promise<void>;
    private onSuccess: () => void;
    private onFailure: (error: Error) => void;

    private scheduler: OperationScheduler;

    constructor(config: IConfig, delegate: IDelegate) {
        this.config = config;
        this.delegate = delegate;

        this.onSuccess = () => {};
        this.onFailure = () => {};
        // tslint:disable-next-line:promise-must-complete
        this.done = new Promise((resolve: () => void, reject: (error: Error) => void) => {
            this.onSuccess = resolve;
            this.onFailure = reject;
        });

        this.scheduler = new OperationScheduler("application", delegate);
    }

    public async dispose(): Promise<void> {
        while (this.agents.size > 0) {
            await Array.from(this.agents.values())[0].dispose();
        }
    }

    public async run(): Promise<void> {
        try {
            const device = await this.getDevice(this.config.targetDevice);
            this.device = device;

            const process = await device.getProcess("sharingd");
            this.process = process;

            await this.instrument(process.pid, process.name);

            this.delegate.onReady();

            await this.done;
        } finally {
            this.dispose();
        }
    }

    private async instrument(pid: number, name: string): Promise<Agent> {
        const agent = await Agent.inject(this.device as frida.Device, pid, name, this.delegate);
        this.agents.set(pid, agent);

        agent.events.once("uninjected", (reason: frida.SessionDetachReason) => {
            this.agents.delete(pid);

            const mainPid = (this.process as frida.Process).pid;
            if (pid === mainPid) {
                switch (reason) {
                    case frida.SessionDetachReason.ApplicationRequested:
                        break;
                    case frida.SessionDetachReason.ProcessReplaced:
                        return;
                    case frida.SessionDetachReason.ProcessTerminated:
                    case frida.SessionDetachReason.ServerTerminated:
                    case frida.SessionDetachReason.DeviceLost:
                        const message = reason[0].toUpperCase() + reason.substr(1).replace(/-/g, " ");
                        this.onFailure(new Error(message));
                        break;
                    default:
                }
            }

            if (this.agents.size === 0) {
                this.onSuccess();
            }
        });

        return agent;
    }

    private async getDevice(targetDevice: TargetDevice): Promise<frida.Device> {
        return this.scheduler.perform("Getting device", async (): Promise<frida.Device> => {
            let device: frida.Device;

            switch (targetDevice.kind) {
                case "local":
                    device = await frida.getLocalDevice();
                    break;
                case "usb":
                    device = await frida.getUsbDevice();
                    break;
                case "remote":
                    device = await frida.getRemoteDevice();
                    break;
                case "by-id":
                    device = await frida.getDevice(targetDevice.id);
                    break;
                default:
                    throw new Error("Invalid target device");
            }

            return device;
        });
    }
}

export interface IDelegate {
    onProgress(operation: IOperation): void;
    onConsoleMessage(scope: string, level: frida.LogLevel, text: string): void;
    onReady(): void;
    onEvent(event: AgentEvent, data: Buffer | null): void;
    onError(error: Error): void;
}

class Agent {
    public pid: number;
    public name: string;
    public scheduler: OperationScheduler;
    public events: EventEmitter = new EventEmitter();

    private delegate: IDelegate;

    private session: frida.Session | null = null;
    private script: frida.Script | null = null;
    private api: IAgent | null = null;

    constructor(pid: number, name: string, delegate: IDelegate) {
        this.pid = pid;
        this.name = name;
        this.scheduler = new OperationScheduler(name, delegate);

        this.delegate = delegate;
    }

    public static async inject(device: frida.Device, pid: number, name: string, delegate: IDelegate): Promise<Agent> {
        const agent = new Agent(pid, name, delegate);
        const {scheduler} = agent;

        try {
            const session = await scheduler.perform(`Attaching to PID ${pid}`, (): Promise<frida.Session> => {
                return device.attach(pid);
            });
            agent.session = session;
            session.detached.connect(agent.onDetached);
            await scheduler.perform("Enabling child gating", (): Promise<void> => {
                return session.enableChildGating();
            });

            const source = await readFile(require.resolve("./agent"), "utf-8");
            const script = await scheduler.perform("Creating script", (): Promise<frida.Script> => {
                return session.createScript(source);
            });
            agent.script = script;
            script.logHandler = agent.onConsoleMessage;
            script.message.connect(agent.onMessage);
            await scheduler.perform("Loading script", (): Promise<void> => {
                return script.load();
            });

            agent.api = script.exports as any as IAgent;

            await scheduler.perform("Initializing", (): Promise<void> => {
                return (agent.api as IAgent).init();
            });
        } catch (e) {
            await agent.dispose();
            throw e;
        }

        return agent;
    }

    public async dispose() {
        const script = this.script;
        if (script !== null) {
            this.script = null;

            await this.scheduler.perform("Unloading script", async (): Promise<void> => {
                try {
                    await script.unload();
                } catch (error) {
                }
            });
        }

        const session = this.session;
        if (session !== null) {
            this.session = null;

            await this.scheduler.perform("Detaching", async (): Promise<void> => {
                try {
                    await session.detach();
                } catch (error) {
                }
            });
        }
    }

    private onDetached = (reason: frida.SessionDetachReason): void => {
        this.events.emit("uninjected", reason);
    };

    private onConsoleMessage = (level: frida.LogLevel, text: string): void => {
        this.delegate.onConsoleMessage(this.name, level, text);
    };

    private onMessage = (message: frida.Message, data: Buffer | null): void => {
        switch (message.type) {
            case frida.MessageType.Send:
                this.delegate.onEvent(message.payload, data);
                break;
            case frida.MessageType.Error:
                const e = new Error(message.description);
                e.stack = message.stack;
                this.delegate.onError(e);
                break;
            default:
        }
    };
}

class OperationScheduler {
    private scope: string;
    private delegate: IDelegate;

    constructor(scope: string, delegate: IDelegate) {
        this.scope = scope;
        this.delegate = delegate;
    }

    public async perform<T>(description: string, work: () => Promise<T>): Promise<T> {
        let result: T;

        const operation = new Operation(this.scope, description);
        this.delegate.onProgress(operation);

        try {
            result = await work();

            operation.complete();
        } catch (error) {
            operation.complete(error);
            throw error;
        }

        return result;
    }
}