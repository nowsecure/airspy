export interface IAgent {
    init(): Promise<void>;
    dispose(): Promise<void>;
}

export type AgentEvent =
    | IRequestHeadEvent
    | IRequestBodyEvent
    | IRequestDeallocatedEvent
    | IResponseEvent
    | ICoverageEvent
    | ILogEvent
    ;

export type RequestId = number;

export interface IEvent {
    type: string;
    timestamp: number;
}

export interface IRequestHeadEvent extends IEvent {
    type: "request-head";
    id: RequestId;
    method: string;
    path: string;
    headers: IHTTPHeader[];
}

export interface IRequestBodyEvent extends IEvent {
    type: "request-body";
    id: RequestId;
}

export interface IRequestDeallocatedEvent extends IEvent {
    type: "request-deallocated";
    id: RequestId;
}

export interface IResponseEvent extends IEvent {
    type: "response";
    id: RequestId;
    responseStatusLine: string;
    headers: IHTTPHeader[];
}

export interface ICoverageEvent extends IEvent {
    type: "coverage";
    id: RequestId;
    modules: string[];
    symbols: string[];
}

export interface ILogEvent extends IEvent {
    type: "log";
    message: string;
}

export interface IHTTPHeader {
    name: string;
    value: string;
}
