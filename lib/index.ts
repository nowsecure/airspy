import * as application from "./application";
import * as config from "./config";
import * as operation from "./operation";

import * as interfaces from "./agent/interfaces";

import * as frida from "frida";

export type Application = application.Application;
export const Application = application.Application;
export type IDelegate = application.IDelegate;

export type IConfig = config.IConfig;
export type TargetDevice = config.TargetDevice;

export type IOperation = operation.IOperation;
export type LogLevel = frida.LogLevel;
export type AgentEvent = interfaces.AgentEvent;
export type RequestId = interfaces.RequestId;
export type IRequestHeadEvent = interfaces.IRequestHeadEvent;
export type IRequestBodyEvent = interfaces.IRequestBodyEvent;
export type IRequestCoverageEvent = interfaces.IRequestCoverageEvent;
export type IRequestDeallocatedEvent = interfaces.IRequestDeallocatedEvent;
export type IResponseEvent = interfaces.IResponseEvent;
export type IHTTPHeader = interfaces.IHTTPHeader;