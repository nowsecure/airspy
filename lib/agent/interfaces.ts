export interface IAgent {
    init(): Promise<void>;
}

export type AgentEvent =
    | IRequestHeadEvent
    | IRequestBodyEvent
    | IRequestCoverageEvent
    | IRequestDeallocatedEvent
    | IResponseEvent
    ;

export type RequestId = number;

export interface IRequestHeadEvent {
    type: "request-head";
    id: RequestId;
    method: string;
    path: string;
    headers: IHTTPHeader[];
}

export interface IRequestBodyEvent {
    type: "request-body";
    id: RequestId;
}

export interface IRequestCoverageEvent {
    type: "request-coverage";
    id: RequestId;
    modules: string[];
    symbols: string[];
}

export interface IRequestDeallocatedEvent {
    type: "request-deallocated";
    id: RequestId;
}

export interface IResponseEvent {
    type: "response";
    id: RequestId;
    responseStatusLine: string;
    headers: IHTTPHeader[];
}

export interface IHTTPHeader {
    name: string;
    value: string;
}
