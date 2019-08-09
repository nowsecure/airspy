import { EventEmitter } from "events";

export type HRTime = any;

export interface IOperation {
    scope: string;
    description: string;
    elapsed: HRTime;
    onceComplete(callback: (error?: Error) => void): void;
}

export class Operation implements IOperation {
    public scope: string;
    public description: string;
    get elapsed(): HRTime {
        if (this.duration === null) {
            return process.hrtime(this.startTime);
        }

        return this.duration;
    }

    private startTime: HRTime;
    private duration: HRTime | null;
    private events: EventEmitter = new EventEmitter();

    constructor(scope: string, description: string) {
        this.scope = scope;
        this.description = description;

        this.startTime = process.hrtime();
        this.duration = null;
    }

    public onceComplete(callback: (error?: Error) => void) {
        this.events.once("complete", callback);
    }

    public complete(error?: Error) {
        this.duration = process.hrtime(this.startTime);
        this.events.emit("complete", error);
    }
}